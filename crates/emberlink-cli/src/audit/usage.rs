//! CLASSIFICATION: PUBLIC
//!
//! `ember audit usage` — multi-daemon disk-footprint surfacing.
//!
//! Anchor: `audit_df_command_landed`.
//!
//! ADR 157 parallel-install topology + ADR 160 retention bound. The prod
//! daemon writes audit state under `~/.ember/audit/` while the dev daemon
//! writes under `~/.ember-dev/audit/`; neither shows up in standard
//! operator habits like `du ~/.ember`, so the first surprise tends to be
//! "my disk is full and emberlink ate 12 GiB." This command sums the
//! footprints for both daemons (or whichever is present), splits the
//! total into primary / archive / sidecar buckets per ADR 160 §C2, and
//! warns / errors when a daemon crosses 80% / 100% of its retention
//! ceiling.
//!
//! ## Layout assumed
//!
//! Per-daemon root: `<home>/{.ember,.ember-dev}/audit/`. Within that:
//!
//! - `primary/` — the live `receipts.sqlite` + its journal + WAL indices.
//!   Today the daemon also writes `daemon.db` at the data-dir root rather
//!   than inside `audit/primary/`; we accept either layout (any
//!   top-level `*.db` / `*.sqlite*` files count as primary).
//! - `archive/` — rotated audit files post-retention.
//! - `sidecar/` — auxiliary blob storage (signed bundle outputs, etc.).
//!
//! Any file under the per-daemon root that doesn't fit a known bucket is
//! charged to `other` so the total never silently undercounts. The MVP
//! does not try to attribute non-`audit/` subdirs (vault, sockets,
//! caches) — those are out of scope for the audit-retention ceiling.
//!
//! ## Ceiling
//!
//! Per the v0.3.0 cohort-defaults reconciliation (Knob 14):
//!
//! - dev0: 5 GiB primary-store size bound
//! - team0: 50 GiB
//! - ent0: per-policy
//!
//! Cohort-aware ceilings require persona-class lookup which isn't wired
//! into this MVP; we apply the dev0 default (5 GiB) universally and note
//! the assumption in the output. The follow-up
//! `META-AP-AUDIT-USAGE-COHORT-AWARE-CEILING` covers the real
//! per-daemon ceiling resolution once the persona-class predicate lands.

use std::fs;
use std::io;
use std::path::{Path, PathBuf};

/// Default ceiling per ADR 160 §C2 + cohort-defaults Knob 14 dev0 row.
/// Cohort-tier ceilings (team0 50 GiB, ent0 per-policy) wire in once the
/// operator-class predicate lands; tracking task
/// `META-AP-AUDIT-USAGE-COHORT-AWARE-CEILING`.
const DEFAULT_CEILING_BYTES: u64 = 5 * 1024 * 1024 * 1024;

const WARN_THRESHOLD_PCT: u8 = 80;
const ERROR_THRESHOLD_PCT: u8 = 100;

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct DaemonUsage {
    pub label: String,
    pub root: PathBuf,
    pub present: bool,
    pub primary_bytes: u64,
    pub archive_bytes: u64,
    pub sidecar_bytes: u64,
    pub other_bytes: u64,
}

impl DaemonUsage {
    pub fn total_bytes(&self) -> u64 {
        self.primary_bytes + self.archive_bytes + self.sidecar_bytes + self.other_bytes
    }

    pub fn ceiling_pct(&self, ceiling: u64) -> u32 {
        if ceiling == 0 {
            return 0;
        }
        let total = self.total_bytes() as f64;
        let ceil = ceiling as f64;
        ((total / ceil) * 100.0).round() as u32
    }

    pub fn severity(&self, ceiling: u64) -> Severity {
        let pct = self.ceiling_pct(ceiling);
        if pct >= ERROR_THRESHOLD_PCT as u32 {
            Severity::Error
        } else if pct >= WARN_THRESHOLD_PCT as u32 {
            Severity::Warn
        } else {
            Severity::Ok
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Severity {
    Ok,
    Warn,
    Error,
}

/// Walk `root` and bucket every regular file's size under primary /
/// archive / sidecar / other. Returns `Err` if `root` exists but is
/// unreadable (permissions, etc.); a missing `root` is reported via the
/// returned `DaemonUsage::present == false`, not an error, so the
/// "ember audit usage" command degrades cleanly when only one daemon is
/// configured on the host.
fn compute_usage(label: &str, root: &Path) -> Result<DaemonUsage, io::Error> {
    let mut usage = DaemonUsage {
        label: label.to_string(),
        root: root.to_path_buf(),
        present: root.is_dir(),
        ..Default::default()
    };
    if !usage.present {
        return Ok(usage);
    }
    walk_and_bucket(root, root, &mut usage)?;
    Ok(usage)
}

fn walk_and_bucket(
    daemon_root: &Path,
    current: &Path,
    usage: &mut DaemonUsage,
) -> Result<(), io::Error> {
    for entry in fs::read_dir(current)? {
        let entry = entry?;
        let path = entry.path();
        let meta = match entry.metadata() {
            Ok(m) => m,
            Err(_) => continue,
        };
        if meta.is_dir() {
            walk_and_bucket(daemon_root, &path, usage)?;
        } else if meta.is_file() {
            let bucket = classify(daemon_root, &path);
            let size = meta.len();
            match bucket {
                Bucket::Primary => usage.primary_bytes += size,
                Bucket::Archive => usage.archive_bytes += size,
                Bucket::Sidecar => usage.sidecar_bytes += size,
                Bucket::Other => usage.other_bytes += size,
            }
        }
    }
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Bucket {
    Primary,
    Archive,
    Sidecar,
    Other,
}

fn classify(daemon_root: &Path, file: &Path) -> Bucket {
    let relative = match file.strip_prefix(daemon_root) {
        Ok(r) => r,
        Err(_) => return Bucket::Other,
    };
    let components: Vec<&str> = relative
        .components()
        .filter_map(|c| c.as_os_str().to_str())
        .collect();
    // Top-level *.db / *.sqlite* files count as primary — the daemon
    // historically writes daemon.db at the data-dir root, not under
    // audit/primary/.
    if components.len() == 1 {
        let name = components[0];
        if name.ends_with(".db")
            || name.ends_with(".sqlite")
            || name.ends_with(".sqlite-wal")
            || name.ends_with(".sqlite-shm")
        {
            return Bucket::Primary;
        }
        return Bucket::Other;
    }
    match components.first().copied() {
        Some("primary") => Bucket::Primary,
        Some("archive") => Bucket::Archive,
        Some("sidecar") => Bucket::Sidecar,
        // `audit/<bucket>/...` — strip the leading `audit` and classify
        // by the second-level dir so a host that puts everything under
        // `audit/` still gets the per-bucket breakdown.
        Some("audit") => match components.get(1).copied() {
            Some("primary") => Bucket::Primary,
            Some("archive") => Bucket::Archive,
            Some("sidecar") => Bucket::Sidecar,
            _ => Bucket::Other,
        },
        _ => Bucket::Other,
    }
}

/// Format bytes as a fixed-width human string. Uses 1024-base because the
/// brief table renders binary prefixes (1.2 GiB, not 1.3 GB).
pub fn format_bytes(bytes: u64) -> String {
    const KIB: f64 = 1024.0;
    let b = bytes as f64;
    if b < KIB {
        return format!("{bytes} B");
    }
    let kib = b / KIB;
    if kib < KIB {
        return format!("{kib:.1} KiB");
    }
    let mib = kib / KIB;
    if mib < KIB {
        return format!("{mib:.1} MiB");
    }
    let gib = mib / KIB;
    if gib < KIB {
        return format!("{gib:.1} GiB");
    }
    let tib = gib / KIB;
    format!("{tib:.2} TiB")
}

/// Produce the rendered table + per-daemon severity flags. Pure — returns
/// the formatted string so the test suite can snapshot it without TTY
/// state. audit_df_command_landed.
pub fn render_report(daemons: &[DaemonUsage], ceiling: u64) -> String {
    let mut out = String::new();
    out.push_str("Audit footprint summary\n");
    out.push_str(&format!(
        "{:<20} {:>10} {:>10} {:>10} {:>10} {:>10}  Status\n",
        "", "Primary", "Archive", "Sidecar", "Other", "Total"
    ));
    let mut grand_total = 0u64;
    let mut warn_daemons: Vec<&str> = Vec::new();
    let mut error_daemons: Vec<&str> = Vec::new();
    for d in daemons {
        if !d.present {
            out.push_str(&format!(
                "{:<20}  (not present at {})\n",
                d.label,
                d.root.display()
            ));
            continue;
        }
        let total = d.total_bytes();
        grand_total += total;
        let sev = d.severity(ceiling);
        match sev {
            Severity::Warn => warn_daemons.push(&d.label),
            Severity::Error => error_daemons.push(&d.label),
            Severity::Ok => {}
        }
        let status = match sev {
            Severity::Ok => format!("{}% of ceiling", d.ceiling_pct(ceiling)),
            Severity::Warn => format!("{}% of ceiling ⚠", d.ceiling_pct(ceiling)),
            Severity::Error => format!("{}% of ceiling ✗", d.ceiling_pct(ceiling)),
        };
        out.push_str(&format!(
            "{:<20} {:>10} {:>10} {:>10} {:>10} {:>10}  {}\n",
            d.label,
            format_bytes(d.primary_bytes),
            format_bytes(d.archive_bytes),
            format_bytes(d.sidecar_bytes),
            format_bytes(d.other_bytes),
            format_bytes(total),
            status,
        ));
    }
    out.push_str(&format!(
        "{:<20} {:>10} {:>10} {:>10} {:>10} {:>10}\n",
        "TOTAL",
        "",
        "",
        "",
        "",
        format_bytes(grand_total),
    ));
    out.push_str(&format!(
        "Per-daemon ceiling: {} (dev0 default per ADR 160 §C2 / cohort-defaults Knob 14)\n",
        format_bytes(ceiling)
    ));
    // Footer lines are independent — a mixed run with one warn-range
    // daemon AND one error-range daemon emits both lines so the
    // operator sees the full posture, not just the highest severity.
    if !warn_daemons.is_empty() {
        out.push_str(&format!(
            "Warning: {} within 80% of ceiling — rotation cadence may be falling behind.\n",
            warn_daemons.join(", ")
        ));
    }
    if !error_daemons.is_empty() {
        out.push_str(&format!(
            "Error: {} at or above 100% of ceiling. Recovery: ember recover audit --scope rotate\n",
            error_daemons.join(", ")
        ));
    }
    out
}

/// Public entry point. Walks the prod + dev daemon audit roots (under
/// `$HOME`), formats the report, prints it, and returns an exit code: 0
/// when every daemon is below 80%, 1 when at least one is in warn range,
/// 2 when at least one is at or above 100%.
pub fn run(home: &Path) -> i32 {
    let prod_root = home.join(".ember").join("audit");
    let dev_root = home.join(".ember-dev").join("audit");
    let prod = compute_usage("Prod daemon", &prod_root).unwrap_or(DaemonUsage {
        label: "Prod daemon".to_string(),
        root: prod_root,
        present: false,
        ..Default::default()
    });
    let dev = compute_usage("Dev daemon", &dev_root).unwrap_or(DaemonUsage {
        label: "Dev daemon".to_string(),
        root: dev_root,
        present: false,
        ..Default::default()
    });
    let daemons = vec![prod, dev];
    let report = render_report(&daemons, DEFAULT_CEILING_BYTES);
    print!("{report}");
    let sev = daemons
        .iter()
        .filter(|d| d.present)
        .map(|d| d.severity(DEFAULT_CEILING_BYTES))
        .max_by_key(|s| *s as u8)
        .unwrap_or(Severity::Ok);
    match sev {
        Severity::Ok => 0,
        Severity::Warn => 1,
        Severity::Error => 2,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::io::Write;

    fn write_file(path: &Path, size: u64) {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).unwrap();
        }
        let mut f = fs::File::create(path).unwrap();
        // Use a one-byte loop instead of zero-filling a giant buffer so
        // the test suite stays cheap even at multi-MiB sizes.
        for _ in 0..size {
            f.write_all(b"x").unwrap();
        }
    }

    #[test]
    fn missing_root_reports_not_present_without_error() {
        let dir = tempfile::tempdir().unwrap();
        let usage = compute_usage("Prod daemon", &dir.path().join("never-existed")).unwrap();
        assert!(!usage.present);
        assert_eq!(usage.total_bytes(), 0);
    }

    #[test]
    fn classifies_top_level_db_as_primary() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        write_file(&root.join("daemon.db"), 1024);
        write_file(&root.join("daemon.db-wal"), 0);
        let usage = compute_usage("Prod daemon", root).unwrap();
        assert!(usage.present);
        assert_eq!(usage.primary_bytes, 1024);
        assert_eq!(usage.archive_bytes, 0);
        assert_eq!(usage.sidecar_bytes, 0);
        assert_eq!(usage.other_bytes, 0);
    }

    #[test]
    fn classifies_per_bucket_subdirs() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        write_file(&root.join("primary").join("receipts.sqlite"), 100);
        write_file(&root.join("archive").join("rotated-2026-04.tar.zst"), 200);
        write_file(&root.join("sidecar").join("bundle-abcd.bin"), 50);
        write_file(&root.join("misc").join("random.log"), 7);
        let usage = compute_usage("Prod daemon", root).unwrap();
        assert_eq!(usage.primary_bytes, 100);
        assert_eq!(usage.archive_bytes, 200);
        assert_eq!(usage.sidecar_bytes, 50);
        assert_eq!(usage.other_bytes, 7);
        assert_eq!(usage.total_bytes(), 357);
    }

    #[test]
    fn classifies_nested_audit_dir_layout() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        write_file(&root.join("audit").join("primary").join("db.sqlite"), 1);
        write_file(&root.join("audit").join("archive").join("a.tar"), 2);
        write_file(&root.join("audit").join("sidecar").join("s.bin"), 4);
        let usage = compute_usage("Prod daemon", root).unwrap();
        assert_eq!(usage.primary_bytes, 1);
        assert_eq!(usage.archive_bytes, 2);
        assert_eq!(usage.sidecar_bytes, 4);
    }

    #[test]
    fn ceiling_pct_below_warn_returns_ok() {
        let u = DaemonUsage {
            primary_bytes: 100,
            ..Default::default()
        };
        // 100 bytes vs 1000-byte ceiling = 10%.
        assert_eq!(u.ceiling_pct(1000), 10);
        assert_eq!(u.severity(1000), Severity::Ok);
    }

    #[test]
    fn ceiling_pct_at_80_returns_warn() {
        // audit_df_command_landed — exercised in the warn-threshold test
        // body so a checkpoint grep covers production + test paths.
        let u = DaemonUsage {
            primary_bytes: 800,
            ..Default::default()
        };
        assert_eq!(u.ceiling_pct(1000), 80);
        assert_eq!(u.severity(1000), Severity::Warn);
    }

    #[test]
    fn ceiling_pct_at_or_above_100_returns_error() {
        let u = DaemonUsage {
            primary_bytes: 1100,
            ..Default::default()
        };
        assert_eq!(u.ceiling_pct(1000), 110);
        assert_eq!(u.severity(1000), Severity::Error);
        let exactly = DaemonUsage {
            primary_bytes: 1000,
            ..Default::default()
        };
        assert_eq!(exactly.severity(1000), Severity::Error);
    }

    #[test]
    fn render_report_emits_warning_at_80() {
        let prod = DaemonUsage {
            label: "Prod daemon".to_string(),
            root: PathBuf::from("/.ember/audit"),
            present: true,
            primary_bytes: 800,
            ..Default::default()
        };
        let dev = DaemonUsage {
            label: "Dev daemon".to_string(),
            root: PathBuf::from("/.ember-dev/audit"),
            present: false,
            ..Default::default()
        };
        let out = render_report(&[prod, dev], 1000);
        assert!(out.contains("Prod daemon"));
        assert!(out.contains("Warning"));
        assert!(out.contains("80% of ceiling"));
    }

    #[test]
    fn render_report_emits_error_at_100_with_recovery_cta() {
        let prod = DaemonUsage {
            label: "Prod daemon".to_string(),
            root: PathBuf::from("/.ember/audit"),
            present: true,
            primary_bytes: 1100,
            ..Default::default()
        };
        let out = render_report(&[prod], 1000);
        assert!(out.contains("Error"));
        assert!(out.contains("100% of ceiling"));
        assert!(out.contains("ember recover audit --scope rotate"));
    }

    #[test]
    fn render_report_handles_only_dev_present() {
        let prod = DaemonUsage {
            label: "Prod daemon".to_string(),
            root: PathBuf::from("/.ember/audit"),
            present: false,
            ..Default::default()
        };
        let dev = DaemonUsage {
            label: "Dev daemon".to_string(),
            root: PathBuf::from("/.ember-dev/audit"),
            present: true,
            primary_bytes: 100,
            ..Default::default()
        };
        let out = render_report(&[prod, dev], 1000);
        assert!(out.contains("(not present at"));
        assert!(out.contains("Dev daemon"));
        assert!(!out.contains("Warning"));
        assert!(!out.contains("Error"));
    }

    #[test]
    fn format_bytes_picks_largest_clean_unit() {
        assert_eq!(format_bytes(0), "0 B");
        assert_eq!(format_bytes(512), "512 B");
        assert_eq!(format_bytes(1024), "1.0 KiB");
        assert_eq!(format_bytes(1024 * 1024), "1.0 MiB");
        assert_eq!(format_bytes(1024 * 1024 * 1024), "1.0 GiB");
        assert_eq!(format_bytes(5 * 1024 * 1024 * 1024), "5.0 GiB");
    }

    #[test]
    fn synthetic_fixture_warn_threshold_round_trip() {
        // T2 acceptance: synthetic fixture with 80% ceiling triggers
        // warning; 110% triggers error.
        let dir = tempfile::tempdir().unwrap();
        let prod_root = dir.path().join(".ember").join("audit");
        let dev_root = dir.path().join(".ember-dev").join("audit");
        let synthetic_ceiling = 1000u64;
        write_file(&prod_root.join("daemon.db"), 800);
        write_file(&dev_root.join("daemon.db"), 1100);
        let prod = compute_usage("Prod daemon", &prod_root).unwrap();
        let dev = compute_usage("Dev daemon", &dev_root).unwrap();
        assert_eq!(prod.severity(synthetic_ceiling), Severity::Warn);
        assert_eq!(dev.severity(synthetic_ceiling), Severity::Error);
        let report = render_report(&[prod, dev], synthetic_ceiling);
        assert!(report.contains("Warning"));
        assert!(report.contains("Error"));
        assert!(report.contains("ember recover audit --scope rotate"));
    }
}
