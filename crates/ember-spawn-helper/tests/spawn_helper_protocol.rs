// CLASSIFICATION: PUBLIC

//! Cross-platform protocol-level integration tests for
//! `ember-spawn-helper`. Exercises the wire types without spawning
//! the helper binary — runs on every host (including the Claude Code
//! sandbox, which blocks fork+execve in tests per project memory
//! `broker_exec_tests_sandbox_blocked`).
//!
//! The macOS-specific `tests/spawn_shim_e2e.rs` covers the actual
//! posix_spawn → shim → execve chain.

use std::path::PathBuf;

use ember_spawn_helper::{HelperFrame, SpawnDirective, WIRE_VERSION, read_frame, write_frame};

#[tokio::test]
async fn protocol_frame_roundtrip_preserves_directive() {
    let d = SpawnDirective {
        protocol_version: WIRE_VERSION,
        binary_path: PathBuf::from("/usr/bin/id"),
        argv: vec!["id".to_string(), "-u".to_string()],
        env: vec![("PATH".to_string(), "/usr/bin".to_string())],
        cwd: PathBuf::from("/"),
        target_uid: 10010,
        target_gid: 10010,
        content_hash_blake3: "0".repeat(64),
        chroot_dir: None,
        sandbox_profile: None,
        seccomp_filter: None,
        invocation_id: Some("01HXAMPLE".to_string()),
    };
    let mut buf: Vec<u8> = Vec::new();
    write_frame(&mut buf, &HelperFrame::Spawn(d.clone()))
        .await
        .expect("encode");
    let mut cursor = std::io::Cursor::new(&buf);
    let frame = read_frame(&mut cursor)
        .await
        .expect("decode")
        .expect("Some");
    match frame {
        HelperFrame::Spawn(got) => assert_eq!(got, d),
        other => panic!("expected Spawn, got {other:?}"),
    }
}

#[tokio::test]
async fn protocol_helper_frame_variants_roundtrip() {
    let variants = vec![
        HelperFrame::Exit {
            code: 0,
            invocation_id: None,
            stdout_tail: String::new(),
            stderr_tail: String::new(),
        },
        HelperFrame::Exit {
            code: 137,
            invocation_id: Some("01HXAMPLE".to_string()),
            stdout_tail: "captured stdout\n".to_string(),
            stderr_tail: "captured stderr\n".to_string(),
        },
        HelperFrame::HashMismatch {
            expected: "aa".to_string(),
            actual: "bb".to_string(),
        },
        HelperFrame::Refused {
            reason: "shim_hash_mismatch".to_string(),
            detail: Some("on-disk=aaaa expected=bbbb".to_string()),
        },
        HelperFrame::Refused {
            reason: "peercred_mismatch".to_string(),
            detail: Some("uid=501 expected=302".to_string()),
        },
    ];
    for frame in variants {
        let mut buf: Vec<u8> = Vec::new();
        write_frame(&mut buf, &frame).await.expect("encode");
        let mut cursor = std::io::Cursor::new(&buf);
        let decoded = read_frame(&mut cursor)
            .await
            .expect("decode")
            .expect("Some");
        assert_eq!(decoded, frame);
    }
}
