use std::{
    ffi::{CStr, CString},
    fs::{self, File, OpenOptions},
    io::{self, Read, Seek, SeekFrom, Write},
    os::{
        fd::{AsRawFd, FromRawFd},
        unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    },
    path::{Path, PathBuf},
};

use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::model::ArtifactRef;

const DIRECTORY_MODE: u32 = 0o700;
const ARTIFACT_MODE: u32 = 0o400;
const COPY_BUFFER_BYTES: usize = 64 * 1024;

/// Private, content-addressed storage for caller-supplied byte streams.
///
/// The store never accepts or exposes an artifact path. A successful open owns
/// the same read-only file descriptor whose contents were verified.
pub struct ArtifactStore {
    root: PathBuf,
    root_directory: File,
    max_bytes: u64,
}

impl ArtifactStore {
    pub fn new(root: impl AsRef<Path>, max_bytes: u64) -> Result<Self, ArtifactError> {
        let root = root.as_ref().to_path_buf();
        fs::create_dir_all(&root)?;
        let metadata = fs::symlink_metadata(&root)?;
        if !metadata.file_type().is_dir() {
            return Err(ArtifactError::InvalidStoreRoot);
        }
        fs::set_permissions(&root, fs::Permissions::from_mode(DIRECTORY_MODE))?;
        let root_directory = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_CLOEXEC | libc::O_DIRECTORY | libc::O_NOFOLLOW)
            .open(&root)?;
        let opened_metadata = root_directory.metadata()?;
        if !opened_metadata.file_type().is_dir()
            || opened_metadata.dev() != metadata.dev()
            || opened_metadata.ino() != metadata.ino()
            || opened_metadata.mode() & 0o777 != DIRECTORY_MODE
        {
            return Err(ArtifactError::InvalidStoreRoot);
        }
        root_directory.sync_all()?;
        Ok(Self {
            root,
            root_directory,
            max_bytes,
        })
    }

    /// Streams an artifact into a private temporary file and atomically links
    /// the fully-synced object into the store under its SHA-256 digest.
    pub fn import(&self, reader: impl Read) -> Result<ArtifactRef, ArtifactError> {
        Ok(self.import_scoped(reader)?.into_reference())
    }

    /// Imports caller bytes and retains the verified directory-entry identity
    /// required to remove this request's exact object after execution.
    pub fn import_scoped(&self, mut reader: impl Read) -> Result<ImportedArtifact, ArtifactError> {
        let mut temporary = tempfile::Builder::new()
            .prefix(".artifact-ingress-")
            .tempfile_in(&self.root)?;
        let (digest, _) = stream_bounded_sha256(
            &mut reader,
            self.max_bytes,
            ArtifactError::SizeLimitExceeded {
                max_bytes: self.max_bytes,
            },
            |chunk| temporary.write_all(chunk),
        )?;

        temporary.flush()?;
        temporary.as_file().sync_all()?;
        temporary
            .as_file()
            .set_permissions(fs::Permissions::from_mode(ARTIFACT_MODE))?;
        temporary.as_file().sync_all()?;

        let reference = ArtifactRef::from_digest(&digest);
        let temporary_metadata = temporary.as_file().metadata()?;
        let destination = self.object_path(&reference);
        let published_new = match fs::hard_link(temporary.path(), &destination) {
            Ok(()) => true,
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => false,
            Err(error) => return Err(error.into()),
        };
        temporary.close()?;
        self.root_directory.sync_all()?;

        let verified = match self.open_verified(&reference) {
            Ok(verified) => verified,
            Err(error) if published_new => {
                let artifact = ImportedArtifact {
                    reference,
                    device: temporary_metadata.dev(),
                    inode: temporary_metadata.ino(),
                };
                self.remove_scoped(&artifact)?;
                return Err(error);
            }
            Err(error) => return Err(error),
        };
        let metadata = verified.file.metadata()?;
        Ok(ImportedArtifact {
            reference,
            device: metadata.dev(),
            inode: metadata.ino(),
        })
    }

    /// Removes only the verified directory entry imported for this request.
    ///
    /// The pinned directory descriptor prevents store-root replacement from
    /// redirecting cleanup. Opening with `O_NOFOLLOW` and checking the captured
    /// device/inode identity prevents a different entry from being removed.
    /// A missing entry is already clean and therefore succeeds.
    #[allow(unsafe_code)]
    pub fn remove_scoped(&self, artifact: &ImportedArtifact) -> Result<(), ArtifactError> {
        let name = object_name(artifact.artifact_ref());
        let file = match open_object_at(&self.root_directory, &name) {
            Ok(file) => file,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
            Err(error) => return Err(error.into()),
        };
        let metadata = file.metadata()?;
        if !metadata.file_type().is_file()
            || metadata.dev() != artifact.device
            || metadata.ino() != artifact.inode
        {
            return Err(ArtifactError::StoredObjectIdentityChanged);
        }

        // SAFETY: the pinned directory descriptor and NUL-terminated digest
        // name remain live for the duration of unlinkat.
        let result = unsafe { libc::unlinkat(self.root_directory.as_raw_fd(), name.as_ptr(), 0) };
        if result != 0 {
            let error = io::Error::last_os_error();
            if error.kind() == io::ErrorKind::NotFound {
                return Ok(());
            }
            return Err(error.into());
        }
        self.root_directory.sync_all()?;
        Ok(())
    }

    /// Opens an object read-only, recomputes its SHA-256 on that descriptor,
    /// and rewinds it before returning it to the caller.
    pub fn open_verified(
        &self,
        reference: &ArtifactRef,
    ) -> Result<VerifiedArtifact, ArtifactError> {
        let name = object_name(reference);
        let mut file = open_object_at(&self.root_directory, &name)?;
        let metadata = file.metadata()?;
        if !metadata.file_type().is_file() {
            return Err(ArtifactError::InvalidStoredObject);
        }

        let (digest, length) = stream_bounded_sha256(
            &mut file,
            self.max_bytes,
            ArtifactError::InvalidStoredObject,
            |_| Ok(()),
        )?;
        let actual = hex::encode(digest);
        if actual != reference.digest_hex() {
            return Err(ArtifactError::Corrupt {
                expected_sha256: reference.digest_hex().to_owned(),
                actual_sha256: actual,
            });
        }
        file.seek(SeekFrom::Start(0))?;

        Ok(VerifiedArtifact {
            file,
            reference: reference.clone(),
            length,
        })
    }

    fn object_path(&self, reference: &ArtifactRef) -> PathBuf {
        self.root.join(reference.digest_hex())
    }
}

/// Request-scoped ownership of one verified content-addressed directory entry.
#[derive(Debug)]
pub struct ImportedArtifact {
    reference: ArtifactRef,
    device: u64,
    inode: u64,
}

impl ImportedArtifact {
    pub fn artifact_ref(&self) -> &ArtifactRef {
        &self.reference
    }

    fn into_reference(self) -> ArtifactRef {
        self.reference
    }
}

/// A read-only artifact descriptor verified immediately before construction.
pub struct VerifiedArtifact {
    file: File,
    reference: ArtifactRef,
    length: u64,
}

impl VerifiedArtifact {
    pub fn artifact_ref(&self) -> &ArtifactRef {
        &self.reference
    }

    pub fn len(&self) -> u64 {
        self.length
    }

    pub fn is_empty(&self) -> bool {
        self.length == 0
    }
}

impl Read for VerifiedArtifact {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        self.file.read(buffer)
    }
}

impl Seek for VerifiedArtifact {
    fn seek(&mut self, position: SeekFrom) -> io::Result<u64> {
        self.file.seek(position)
    }
}

fn object_name(reference: &ArtifactRef) -> CString {
    CString::new(reference.digest_hex()).expect("validated artifact digest")
}

fn stream_bounded_sha256(
    reader: &mut impl Read,
    max_bytes: u64,
    limit_error: ArtifactError,
    mut write_chunk: impl FnMut(&[u8]) -> io::Result<()>,
) -> Result<([u8; 32], u64), ArtifactError> {
    let mut digest = Sha256::new();
    let mut length = 0_u64;
    let mut buffer = [0_u8; COPY_BUFFER_BYTES];

    loop {
        let read = reader.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        let Some(next_length) = length
            .checked_add(read as u64)
            .filter(|length| *length <= max_bytes)
        else {
            return Err(limit_error);
        };
        length = next_length;
        digest.update(&buffer[..read]);
        write_chunk(&buffer[..read])?;
    }

    Ok((digest.finalize().into(), length))
}

#[allow(unsafe_code)]
fn open_object_at(directory: &File, name: &CStr) -> io::Result<File> {
    // SAFETY: the pinned directory descriptor and NUL-terminated digest name
    // remain live for the duration of openat.
    let descriptor = unsafe {
        libc::openat(
            directory.as_raw_fd(),
            name.as_ptr(),
            libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
        )
    };
    if descriptor < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: a successful openat returns one newly owned descriptor.
    Ok(unsafe { File::from_raw_fd(descriptor) })
}

#[derive(Debug, Error)]
pub enum ArtifactError {
    #[error("artifact store root is not a directory")]
    InvalidStoreRoot,
    #[error("artifact exceeds the configured {max_bytes}-byte limit")]
    SizeLimitExceeded { max_bytes: u64 },
    #[error("stored artifact is not a valid regular object")]
    InvalidStoredObject,
    #[error("stored artifact directory entry no longer has its verified identity")]
    StoredObjectIdentityChanged,
    #[error("stored artifact is corrupt: expected {expected_sha256}, got {actual_sha256}")]
    Corrupt {
        expected_sha256: String,
        actual_sha256: String,
    },
    #[error("artifact I/O failed: {0}")]
    Io(#[from] io::Error),
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn duplicate_content_reuses_one_immutable_object() {
        let directory = tempfile::tempdir().unwrap();
        let store = ArtifactStore::new(directory.path(), 1024).unwrap();

        let first = store.import(Cursor::new(b"same bytes")).unwrap();
        let second = store.import(Cursor::new(b"same bytes")).unwrap();

        assert_eq!(first, second);
        assert_eq!(fs::read_dir(directory.path()).unwrap().count(), 1);
        assert_eq!(
            fs::metadata(directory.path()).unwrap().permissions().mode() & 0o777,
            DIRECTORY_MODE
        );
        assert_eq!(
            fs::metadata(directory.path().join(first.digest_hex()))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            ARTIFACT_MODE
        );
    }

    #[test]
    fn verified_open_refuses_corrupt_stored_bytes() {
        let directory = tempfile::tempdir().unwrap();
        let store = ArtifactStore::new(directory.path(), 1024).unwrap();
        let reference = store.import(Cursor::new(b"trusted")).unwrap();
        let object = directory.path().join(reference.digest_hex());
        fs::set_permissions(&object, fs::Permissions::from_mode(0o600)).unwrap();
        fs::write(&object, b"altered").unwrap();
        fs::set_permissions(&object, fs::Permissions::from_mode(ARTIFACT_MODE)).unwrap();

        assert!(matches!(
            store.open_verified(&reference),
            Err(ArtifactError::Corrupt { .. })
        ));
    }

    #[test]
    fn ingress_enforces_size_bound_without_publishing_an_object() {
        let directory = tempfile::tempdir().unwrap();
        let store = ArtifactStore::new(directory.path(), 4).unwrap();

        assert!(matches!(
            store.import(Cursor::new(b"12345")),
            Err(ArtifactError::SizeLimitExceeded { max_bytes: 4 })
        ));
        assert_eq!(fs::read_dir(directory.path()).unwrap().count(), 0);
    }

    #[test]
    fn digest_bound_is_inclusive_for_ingress_and_verification() {
        let directory = tempfile::tempdir().unwrap();
        let importing_store = ArtifactStore::new(directory.path(), 4).unwrap();
        let reference = importing_store.import(Cursor::new(b"1234")).unwrap();

        assert_eq!(importing_store.open_verified(&reference).unwrap().len(), 4);

        let stricter_store = ArtifactStore::new(directory.path(), 3).unwrap();
        assert!(matches!(
            stricter_store.open_verified(&reference),
            Err(ArtifactError::InvalidStoredObject)
        ));
    }

    #[test]
    fn scoped_removal_is_idempotent_and_open_descriptor_remains_readable() {
        let directory = tempfile::tempdir().unwrap();
        let store = ArtifactStore::new(directory.path(), 1024).unwrap();
        let artifact = store.import_scoped(Cursor::new(b"request bytes")).unwrap();
        let mut opened = store.open_verified(artifact.artifact_ref()).unwrap();

        store.remove_scoped(&artifact).unwrap();
        store.remove_scoped(&artifact).unwrap();

        assert!(
            !directory
                .path()
                .join(artifact.artifact_ref().digest_hex())
                .exists()
        );
        let mut retained = Vec::new();
        opened.read_to_end(&mut retained).unwrap();
        assert_eq!(retained, b"request bytes");
    }

    #[test]
    fn scoped_removal_stays_bound_to_pinned_store_directory() {
        let parent = tempfile::tempdir().unwrap();
        let store_path = parent.path().join("store");
        let displaced_path = parent.path().join("displaced-store");
        let store = ArtifactStore::new(&store_path, 1024).unwrap();
        let artifact = store.import_scoped(Cursor::new(b"owned")).unwrap();
        let object_name = artifact.artifact_ref().digest_hex();

        fs::rename(&store_path, &displaced_path).unwrap();
        fs::create_dir(&store_path).unwrap();
        fs::write(store_path.join(object_name), b"unrelated replacement").unwrap();

        store.remove_scoped(&artifact).unwrap();

        assert!(!displaced_path.join(object_name).exists());
        assert_eq!(
            fs::read(store_path.join(object_name)).unwrap(),
            b"unrelated replacement"
        );
    }

    #[test]
    fn scoped_removal_refuses_replaced_directory_entry() {
        let directory = tempfile::tempdir().unwrap();
        let store = ArtifactStore::new(directory.path(), 1024).unwrap();
        let artifact = store.import_scoped(Cursor::new(b"owned")).unwrap();
        let object = directory.path().join(artifact.artifact_ref().digest_hex());
        fs::remove_file(&object).unwrap();
        fs::write(&object, b"unrelated replacement").unwrap();

        assert!(matches!(
            store.remove_scoped(&artifact),
            Err(ArtifactError::StoredObjectIdentityChanged)
        ));
        assert_eq!(fs::read(object).unwrap(), b"unrelated replacement");
    }

    #[test]
    fn scoped_removal_never_follows_replacement_symlink() {
        let parent = tempfile::tempdir().unwrap();
        let store_path = parent.path().join("store");
        let target = parent.path().join("unrelated-target");
        let store = ArtifactStore::new(&store_path, 1024).unwrap();
        let artifact = store.import_scoped(Cursor::new(b"owned")).unwrap();
        let object = store_path.join(artifact.artifact_ref().digest_hex());
        fs::remove_file(&object).unwrap();
        fs::write(&target, b"unrelated replacement").unwrap();
        std::os::unix::fs::symlink(&target, &object).unwrap();

        assert!(matches!(
            store.remove_scoped(&artifact),
            Err(ArtifactError::Io(_))
        ));
        assert_eq!(fs::read(&target).unwrap(), b"unrelated replacement");
        assert!(
            fs::symlink_metadata(object)
                .unwrap()
                .file_type()
                .is_symlink()
        );
    }
}
