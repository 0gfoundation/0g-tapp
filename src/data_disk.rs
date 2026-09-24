//! Finding and provisioning the persistent disk that `/data` lives on.
//!
//! The root filesystem of a CVM image is a RAM overlay, so everything that must outlive a
//! reboot — container stores, per-app encrypted volumes, file logs — lives on a separate
//! disk mounted at `/data`. A node without it runs but can host nothing.
//!
//! `tapp-data-provision.service` handles the common case at boot: exactly one blank attached
//! disk gets formatted and labelled `tapp-data`, and every later boot finds it by label with
//! no guessing at all. What it deliberately will not do is choose between several disks, and
//! that is not a rare corner:
//!
//! * every GPU machine type has ephemeral cloud scratch disks attached that cannot be
//!   declined — `a3-highgpu-1g` carries two, so the candidate set is never a single disk;
//! * bare metal normally has more than one spare disk.
//!
//! On those hosts boot-time provisioning refuses, and before this module the only way
//! forward was a shell — which a hardened image does not have. The node was simply, silently
//! useless. This module is the same logic reachable over the API, where the owner names the
//! disk instead of the node guessing.
//!
//! Every rule here is deliberately conservative: an existing filesystem is never destroyed,
//! ephemeral scratch is never chosen by itself, and the boot disk is never a candidate.

use std::path::Path;
use std::process::Command;

use tracing::{info, warn};

/// Where the persistent disk is mounted. Also the prefix of every durable path in the image
/// (`/data/docker`, `/data/containerd`, `/data/log/tapp`), so "is this mounted" answers "can
/// this node keep anything".
pub const DATA_MOUNTPOINT: &str = "/data";

/// The filesystem label the whole scheme turns on: once a disk carries it, provisioning
/// short-circuits on every later boot and no heuristic runs at all.
pub const DATA_LABEL: &str = "tapp-data";

/// A disk that could plausibly become `/data`.
#[derive(Debug, Clone)]
pub struct Candidate {
    pub device: String,
    pub size_bytes: u64,
    /// Empty when the disk carries no filesystem signature.
    pub filesystem: String,
    /// Empty when unlabelled.
    pub label: String,
    /// Ephemeral cloud scratch. Never chosen automatically; may be named explicitly.
    pub ephemeral: bool,
    /// Model string as the kernel reports it, e.g. `nvme_card-pd`.
    pub model: String,
}

/// What provisioning did, or would do.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    /// The disk was blank and got a fresh filesystem.
    Formatted,
    /// The disk already held ext4; it was relabelled and its contents kept.
    Adopted,
    /// A `tapp-data` disk was already present; nothing to do.
    AlreadyProvisioned,
}

impl Action {
    pub fn as_str(self) -> &'static str {
        match self {
            Action::Formatted => "formatted",
            Action::Adopted => "adopted",
            Action::AlreadyProvisioned => "already_provisioned",
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum DataDiskError {
    #[error("no candidate data disk found; attach one, or pre-label it with: mkfs.ext4 -L {DATA_LABEL} <device>")]
    NoCandidate,

    #[error("several candidate disks ({0}); refusing to guess which one is {DATA_MOUNTPOINT}. Name one explicitly")]
    Ambiguous(String),

    #[error("{0} is not a block device this node considers usable for {DATA_MOUNTPOINT}")]
    NotACandidate(String),

    #[error("{device} already carries a {filesystem} filesystem; refusing to destroy it. Only a blank disk or an existing ext4 one can be provisioned")]
    OccupiedByForeignFs { device: String, filesystem: String },

    #[error("{0}")]
    CommandFailed(String),
}

/// Is `/data` a mount point — i.e. does this node have somewhere durable to write?
///
/// Compared by device id against its parent rather than by reading `/proc/mounts`, so a
/// directory that merely *exists* on the RAM overlay (which is exactly what an unmounted
/// `/data` looks like) is correctly reported as absent.
pub fn is_data_mounted() -> bool {
    is_mountpoint(Path::new(DATA_MOUNTPOINT))
}

fn is_mountpoint(path: &Path) -> bool {
    use std::os::unix::fs::MetadataExt;
    let Ok(here) = std::fs::metadata(path) else {
        return false;
    };
    let Some(parent) = path.parent() else {
        return false;
    };
    match std::fs::metadata(parent) {
        Ok(up) => here.dev() != up.dev(),
        Err(_) => false,
    }
}

/// True when `path` (or, if it does not exist yet, its nearest existing ancestor) sits on the
/// same filesystem as `/`.
///
/// This is what stops a missing data disk from turning into a silent one. `/data/log/tapp` is
/// an ordinary path: with the disk unmounted, `create_dir_all` cheerfully creates it on the
/// RAM overlay and logging "works" until the RAM fills or the machine reboots. Asking whether
/// the path would land on the root filesystem catches that before anything is written, and
/// says nothing about `/data` specifically, so it holds for any configured location.
pub fn resolves_onto_root_fs(path: &Path) -> bool {
    use std::os::unix::fs::MetadataExt;
    let Ok(root) = std::fs::metadata("/") else {
        return false;
    };
    let mut cur = path;
    loop {
        if let Ok(md) = std::fs::metadata(cur) {
            return md.dev() == root.dev();
        }
        match cur.parent() {
            Some(p) => cur = p,
            None => return false,
        }
    }
}

fn run(cmd: &str, args: &[&str]) -> Result<String, DataDiskError> {
    let out = Command::new(cmd)
        .args(args)
        .output()
        .map_err(|e| DataDiskError::CommandFailed(format!("{cmd}: {e}")))?;
    if !out.status.success() {
        return Err(DataDiskError::CommandFailed(format!(
            "{} {}: {}",
            cmd,
            args.join(" "),
            String::from_utf8_lossy(&out.stderr).trim()
        )));
    }
    Ok(String::from_utf8_lossy(&out.stdout).to_string())
}

/// The disk carrying the ESP, which must never be touched.
fn boot_disk() -> Option<String> {
    let esp = run("blkid", &["-L", "UEFI"]).ok()?;
    let esp = esp.trim();
    if esp.is_empty() {
        return None;
    }
    let pk = run("lsblk", &["-no", "pkname", esp]).ok()?;
    pk.lines().next().map(|s| s.trim().to_string())
}

/// Ephemeral cloud scratch, which must never be chosen automatically.
///
/// GCP's own `/dev/disk/by-id/google-local-nvme-ssd-N` aliases are not available here: those
/// udev rules ship in `google-guest-configs`, which these images deliberately do not install.
/// What is left is the NVMe model string, which GCP sets to `nvme_card-pd` for a persistent
/// disk and `nvme_card<N>` (`nvme_card0`, `nvme_card1`, …) for each local SSD — so the test is
/// on the prefix, not on a fixed string. Measured on `a3-highgpu-1g`.
fn is_ephemeral(name: &str, model: &str) -> bool {
    if let Ok(entries) = std::fs::read_dir("/dev/disk/by-id") {
        for e in entries.flatten() {
            let alias = e.file_name().to_string_lossy().to_string();
            let looks_scratch = alias.contains("local-nvme-ssd")
                || alias.contains("local-ssd")
                || alias.contains("ephemeral");
            if !looks_scratch {
                continue;
            }
            if let Ok(target) = std::fs::canonicalize(e.path()) {
                if target == Path::new("/dev").join(name) {
                    return true;
                }
            }
        }
    }
    model != "nvme_card-pd" && model.starts_with("nvme_card")
}

fn model_of(name: &str) -> String {
    std::fs::read_to_string(format!("/sys/block/{name}/device/model"))
        .map(|s| s.trim().to_string())
        .unwrap_or_default()
}

/// Every whole disk that is not the boot disk and carries no partitions.
///
/// Ephemeral disks are listed rather than hidden: an operator reading the list should see
/// everything the node saw, including what it declined to choose and why.
pub fn candidates() -> Result<Vec<Candidate>, DataDiskError> {
    let boot = boot_disk().unwrap_or_default();
    let listing = run("lsblk", &["-dnbo", "NAME,TYPE,SIZE"])?;

    let mut out = Vec::new();
    for line in listing.lines() {
        let mut f = line.split_whitespace();
        let (Some(name), Some(kind), Some(size)) = (f.next(), f.next(), f.next()) else {
            continue;
        };
        if kind != "disk" {
            continue;
        }
        // Real disks only — skip zram, loop, device-mapper, optical.
        if !(name.starts_with("sd") || name.starts_with("nvme") || name.starts_with("vd")) {
            continue;
        }
        if name == boot {
            continue;
        }
        // A partitioned disk belongs to something already.
        if let Ok(parts) = run("lsblk", &["-rno", "NAME", &format!("/dev/{name}")]) {
            if parts.lines().count() > 1 {
                continue;
            }
        }
        let device = format!("/dev/{name}");
        let model = model_of(name);
        out.push(Candidate {
            size_bytes: size.parse().unwrap_or(0),
            filesystem: run("blkid", &["-p", "-s", "TYPE", "-o", "value", &device])
                .unwrap_or_default()
                .trim()
                .to_string(),
            label: run("blkid", &["-s", "LABEL", "-o", "value", &device])
                .unwrap_or_default()
                .trim()
                .to_string(),
            ephemeral: is_ephemeral(name, &model),
            model,
            device,
        });
    }
    Ok(out)
}

/// The single disk to use when the caller named none — the same rule boot-time provisioning
/// applies, retried on demand.
fn auto_choose(cands: &[Candidate]) -> Result<&Candidate, DataDiskError> {
    let usable: Vec<&Candidate> = cands.iter().filter(|c| !c.ephemeral).collect();
    match usable.len() {
        0 => Err(DataDiskError::NoCandidate),
        1 => Ok(usable[0]),
        _ => Err(DataDiskError::Ambiguous(
            usable
                .iter()
                .map(|c| c.device.as_str())
                .collect::<Vec<_>>()
                .join(", "),
        )),
    }
}

/// Outcome of a provisioning attempt.
pub struct Provisioned {
    pub device: String,
    pub action: Action,
    pub candidates: Vec<Candidate>,
    pub data_mounted: bool,
    /// Filesystem UUID of the disk that became /data, empty on a dry run.
    ///
    /// The device path is whatever the kernel happened to enumerate this boot and means
    /// nothing later; the UUID is written into the filesystem and identifies it for good. It is
    /// what goes into the measured event, so "which disk is this node's /data" stays an
    /// answerable question after a reboot renames everything.
    pub fs_uuid: String,
}

/// Filesystem UUID of `device`, or empty if it has none.
pub fn fs_uuid(device: &str) -> String {
    run("blkid", &["-s", "UUID", "-o", "value", device])
        .unwrap_or_default()
        .trim()
        .to_string()
}

/// Format or adopt `device` (or the sole candidate when `device` is `None`), label it
/// `tapp-data` and mount `/data`.
///
/// With `dry_run` nothing is written: the chosen device and the action that *would* be taken
/// come back, which is how a caller inspects the candidate list before committing.
pub fn provision(device: Option<&str>, dry_run: bool) -> Result<Provisioned, DataDiskError> {
    let cands = candidates()?;

    // Already done? Say so rather than touching anything. This also makes the call
    // idempotent, so a retry after a partial failure is safe.
    if let Ok(existing) = run("blkid", &["-L", DATA_LABEL]) {
        if !existing.trim().is_empty() {
            let dev = existing.trim().to_string();
            let mounted = if dry_run {
                is_data_mounted()
            } else {
                mount_data()?
            };
            let uuid = fs_uuid(&dev);
            return Ok(Provisioned {
                device: dev,
                action: Action::AlreadyProvisioned,
                candidates: cands,
                data_mounted: mounted,
                fs_uuid: uuid,
            });
        }
    }

    let chosen: Candidate = match device {
        Some(d) => cands
            .iter()
            .find(|c| c.device == d)
            .cloned()
            .ok_or_else(|| DataDiskError::NotACandidate(d.to_string()))?,
        None => auto_choose(&cands)?.clone(),
    };

    // Never destroy a filesystem we did not put there. ext4 is the one exception and it is
    // not an exception to the rule: relabelling keeps every byte.
    let action = match chosen.filesystem.as_str() {
        "" => Action::Formatted,
        "ext4" => Action::Adopted,
        other => {
            return Err(DataDiskError::OccupiedByForeignFs {
                device: chosen.device.clone(),
                filesystem: other.to_string(),
            })
        }
    };

    if dry_run {
        return Ok(Provisioned {
            device: chosen.device,
            action,
            candidates: cands,
            data_mounted: is_data_mounted(),
            fs_uuid: String::new(),
        });
    }

    match action {
        Action::Formatted => {
            info!(device = %chosen.device, "formatting blank disk as LABEL={DATA_LABEL}");
            run("mkfs.ext4", &["-q", "-F", "-L", DATA_LABEL, &chosen.device])?;
        }
        Action::Adopted => {
            info!(device = %chosen.device, "adopting existing ext4 (data preserved)");
            run("e2label", &[&chosen.device, DATA_LABEL])?;
        }
        Action::AlreadyProvisioned => unreachable!("handled above"),
    }

    let mounted = mount_data()?;
    let uuid = fs_uuid(&chosen.device);
    Ok(Provisioned {
        device: chosen.device,
        action,
        candidates: cands,
        data_mounted: mounted,
        fs_uuid: uuid,
    })
}

/// Mount `/data` and start the units that were held back waiting for it.
///
/// `data.mount` comes from the image's fstab entry, so systemd owns the mount; docker and
/// containerd carry `RequiresMountsFor=/data` and stay down until it exists, which is why
/// they are nudged here rather than left for the next reboot.
fn mount_data() -> Result<bool, DataDiskError> {
    if is_data_mounted() {
        return Ok(true);
    }
    run("systemctl", &["daemon-reload"])?;
    run("systemctl", &["start", "data.mount"])?;
    if !is_data_mounted() {
        return Ok(false);
    }
    for unit in ["containerd", "docker"] {
        if let Err(e) = run("systemctl", &["start", unit]) {
            // Not fatal: the disk is mounted, which is the part that needed a human.
            warn!(unit, error = %e, "could not start unit after mounting /data");
        }
    }
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cand(device: &str, ephemeral: bool) -> Candidate {
        Candidate {
            device: device.to_string(),
            size_bytes: 0,
            filesystem: String::new(),
            label: String::new(),
            ephemeral,
            model: String::new(),
        }
    }

    #[test]
    fn scratch_is_recognised_by_model_prefix_not_a_fixed_string() {
        // Measured on GCP a3-highgpu-1g: the persistent disk reports nvme_card-pd, the two
        // local SSDs report nvme_card0 and nvme_card1. An earlier version compared against
        // the exact string "nvme_card" and matched neither, which is the bug this pins.
        assert!(is_ephemeral("nvme1n1", "nvme_card0"));
        assert!(is_ephemeral("nvme2n1", "nvme_card1"));
        assert!(!is_ephemeral("nvme0n2", "nvme_card-pd"));
        // Anything that is not GCP NVMe is left alone; the by-id check covers those images.
        assert!(!is_ephemeral("vdb", ""));
        assert!(!is_ephemeral("sdb", "QEMU HARDDISK"));
    }

    #[test]
    fn auto_choice_ignores_scratch_and_still_refuses_a_real_tie() {
        // The a3-highgpu-1g layout: two local SSDs plus one attached data disk.
        let gpu_host = vec![
            cand("/dev/nvme1n1", true),
            cand("/dev/nvme2n1", true),
            cand("/dev/nvme0n2", false),
        ];
        assert_eq!(auto_choose(&gpu_host).unwrap().device, "/dev/nvme0n2");

        // Two genuine spares (bare metal) is a tie no rule should break by itself.
        let bare_metal = vec![cand("/dev/sdb", false), cand("/dev/sdc", false)];
        assert!(matches!(
            auto_choose(&bare_metal),
            Err(DataDiskError::Ambiguous(_))
        ));

        // Scratch only: nothing durable is on offer, and scratch must not be substituted.
        let scratch_only = vec![cand("/dev/nvme1n1", true)];
        assert!(matches!(
            auto_choose(&scratch_only),
            Err(DataDiskError::NoCandidate)
        ));
    }
}
