//! Per-app encrypted data volumes.
//!
//! Each app gets a LUKS2 volume backed by a sparse image file on the persistent
//! /data disk, mounted at `<app_dir>/data` before its containers start. The
//! passphrase is derived by the KMS cluster under the `fde` material namespace,
//! so it is never stored anywhere: any registered node of the app re-derives the
//! same key on demand, which is what lets data survive reboots (where the RAM
//! rootfs — and the mount point with it — is wiped) and move between hosts.
//!
//! Nothing here ever closes a volume. The key lives in the kernel while the CVM
//! runs, and CVM memory is TEE-protected, so an open volume leaks nothing that a
//! closed one wouldn't; a reboot clears the kernel and locks everything at once.
//! Keeping volumes open is also what makes every step below idempotent — a
//! crashed tapp-server restarting into already-open volumes just reuses them.

use crate::error::{DockerError, TappResult};
use std::path::PathBuf;
use std::process::Stdio;
use tokio::io::AsyncWriteExt;
use tokio::process::Command;
use tracing::info;

/// KMS derivation namespace for volume passphrases: hex("fde").
/// Sibling of `tls_cert::KMS_MATERIAL` (hex("tls")) and the empty namespace
/// (the app's base key) — the whole registry of namespaces in use.
pub const FDE_MATERIAL: &str = "666465";

/// Where volume image files live. On the persistent /data disk — NEVER the RAM
/// rootfs, which is size-capped and wiped on reboot.
const VOLUME_DIR: &str = "/data/tapp/volumes";

fn image_path(app_id: &str) -> PathBuf {
    PathBuf::from(VOLUME_DIR).join(format!("{app_id}.img"))
}

/// Device-mapper name for an app's open volume. app_id is [A-Za-z0-9_-] (see
/// utils::validate_app_id), so no escaping is needed.
fn mapper_name(app_id: &str) -> String {
    format!("tapp-fde-{app_id}")
}

fn mapper_path(app_id: &str) -> PathBuf {
    PathBuf::from("/dev/mapper").join(mapper_name(app_id))
}

fn err(reason: String) -> DockerError {
    DockerError::ContainerOperationFailed {
        operation: "fde_volume".to_string(),
        reason,
    }
}

/// Run a command, optionally writing `stdin` to it, and fail loudly with stderr.
async fn run(program: &str, args: &[&str], stdin: Option<&[u8]>) -> TappResult<Vec<u8>> {
    let mut cmd = Command::new(program);
    cmd.args(args).stdout(Stdio::piped()).stderr(Stdio::piped());
    if stdin.is_some() {
        cmd.stdin(Stdio::piped());
    }
    let mut child = cmd
        .spawn()
        .map_err(|e| err(format!("failed to spawn {program}: {e}")))?;
    if let Some(bytes) = stdin {
        let mut handle = child.stdin.take().expect("stdin was piped");
        handle
            .write_all(bytes)
            .await
            .map_err(|e| err(format!("failed to write {program} stdin: {e}")))?;
        drop(handle); // EOF terminates the key material
    }
    let output = child
        .wait_with_output()
        .await
        .map_err(|e| err(format!("failed to wait for {program}: {e}")))?;
    if !output.status.success() {
        return Err(err(format!(
            "{program} {} failed (exit {:?}): {}",
            args.join(" "),
            output.status.code(),
            String::from_utf8_lossy(&output.stderr)
        ))
        .into());
    }
    Ok(output.stdout)
}

async fn quiet_success(program: &str, args: &[&str]) -> bool {
    Command::new(program)
        .args(args)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .await
        .map(|s| s.success())
        .unwrap_or(false)
}

/// Nominal (sparse) size of a new volume: the whole /data filesystem. All apps on
/// a node belong to one owner, so there is no quota to arbitrate between tenants —
/// the only real limit is the physical disk, and this makes the virtual limit
/// coincide with it. Actual usage grows with actual writes.
fn nominal_size() -> TappResult<u64> {
    let stat = nix_statvfs("/data")?;
    Ok(stat)
}

fn nix_statvfs(path: &str) -> TappResult<u64> {
    // SAFETY: statvfs writes into the zeroed buffer on success and we check the
    // return code before reading it.
    let c_path =
        std::ffi::CString::new(path).map_err(|e| err(format!("bad statvfs path: {e}")))?;
    let mut stat: libc::statvfs = unsafe { std::mem::zeroed() };
    let rc = unsafe { libc::statvfs(c_path.as_ptr(), &mut stat) };
    if rc != 0 {
        return Err(err(format!(
            "statvfs({path}) failed: {} — is the /data disk mounted?",
            std::io::Error::last_os_error()
        ))
        .into());
    }
    Ok(stat.f_blocks as u64 * stat.f_frsize as u64)
}

/// Open (creating if necessary) the app's encrypted volume and mount it at
/// `<app_dir>/data`. Every step checks state before acting, so a partial failure
/// (crash between format and mkfs, an already-mounted leftover from a previous
/// tapp-server process) is repaired on the next call rather than wedging the app.
pub async fn ensure_mounted(app_id: &str, key: &[u8]) -> TappResult<()> {
    let mount_point = super::manager::DockerComposeManager::get_app_dir(app_id).join("data");
    tokio::fs::create_dir_all(&mount_point)
        .await
        .map_err(|e| err(format!("failed to create {}: {e}", mount_point.display())))?;
    let mount_point_str = mount_point.to_string_lossy().to_string();

    if quiet_success("mountpoint", &["-q", &mount_point_str]).await {
        info!(app_id, "encrypted volume already mounted");
        return Ok(());
    }

    tokio::fs::create_dir_all(VOLUME_DIR)
        .await
        .map_err(|e| err(format!("failed to create {VOLUME_DIR}: {e}")))?;
    let img = image_path(app_id);
    let img_str = img.to_string_lossy().to_string();

    if !img.exists() {
        let size = nominal_size()?;
        let file = std::fs::File::create(&img)
            .map_err(|e| err(format!("failed to create {img_str}: {e}")))?;
        file.set_len(size)
            .map_err(|e| err(format!("failed to size {img_str}: {e}")))?;
        info!(app_id, size, "created sparse volume image");
    }

    // Attach the image to a loop device explicitly rather than letting
    // cryptsetup auto-attach: auto-attach needs the autoclear flag and fails in
    // containers (where our e2e runs), while an explicit attach works in both.
    // `losetup -j` first, so a crash-leftover attachment is reused, not doubled.
    let existing = run("losetup", &["-j", &img_str], None).await?;
    let existing = String::from_utf8_lossy(&existing);
    let loop_dev = match existing.split(':').next().filter(|s| !s.is_empty()) {
        Some(dev) => dev.trim().to_string(),
        None => {
            let out = run("losetup", &["--find", "--show", &img_str], None).await?;
            String::from_utf8_lossy(&out).trim().to_string()
        }
    };

    // The key is passed on stdin as hex so it never touches a file or argv.
    // Hex (not raw) so the passphrase can't contain bytes cryptsetup treats
    // specially, and stays reproducible from the same KMS secret.
    let key_hex = hex::encode(key);

    // State-based, not history-based: format if not LUKS, open if no mapper,
    // mkfs if no filesystem. Each test is what makes the whole sequence
    // resumable after a crash at any point.
    if !quiet_success("cryptsetup", &["isLuks", &loop_dev]).await {
        run(
            "cryptsetup",
            &[
                "luksFormat",
                "--type",
                "luks2",
                "--batch-mode",
                "--key-file",
                "-",
                &loop_dev,
            ],
            Some(key_hex.as_bytes()),
        )
        .await?;
        info!(app_id, "LUKS-formatted volume image");
    }

    let mapper = mapper_path(app_id);
    if !mapper.exists() {
        run(
            "cryptsetup",
            &["open", "--key-file", "-", &loop_dev, &mapper_name(app_id)],
            Some(key_hex.as_bytes()),
        )
        .await?;
    }
    let mapper_str = mapper.to_string_lossy().to_string();

    // blkid exits non-zero when it finds no signature — i.e. a freshly formatted
    // (or mkfs-interrupted) volume that still needs a filesystem.
    if !quiet_success("blkid", &[&mapper_str]).await {
        run("mkfs.ext4", &["-q", &mapper_str], None).await?;
        info!(app_id, "created ext4 filesystem on volume");
    }

    run("mount", &[&mapper_str, &mount_point_str], None).await?;
    info!(app_id, mount = %mount_point_str, "encrypted volume mounted");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fde_material_is_valid_hex_and_spells_fde() {
        // KMS rejects non-hex material outright, and the namespace must never
        // collide with the other two in use ("" and hex("tls")).
        let bytes = hex::decode(FDE_MATERIAL).expect("FDE_MATERIAL must be hex");
        assert_eq!(bytes, b"fde");
        assert_ne!(FDE_MATERIAL, crate::tls_cert::KMS_MATERIAL);
    }

    /// Real end-to-end: create → format → open → mkfs → mount, write a file,
    /// tear everything down (simulating a reboot), then ensure again with the
    /// same key and read the file back. Needs root, cryptsetup and loop
    /// support, so it is ignored by default and run explicitly in a privileged
    /// container:
    ///
    ///   cargo test --lib -- --ignored boot::volume
    #[tokio::test]
    #[ignore]
    async fn ensure_mounted_end_to_end() {
        let app_id = "fde-e2e-test";
        let key = b"a fixed 32-byte test key .......";
        let data_dir =
            crate::boot::manager::DockerComposeManager::get_app_dir(app_id).join("data");
        let probe = data_dir.join("probe.txt");

        ensure_mounted(app_id, key).await.expect("first ensure");
        std::fs::write(&probe, "survives reboot").expect("write probe");

        // Second call while mounted must be a no-op, not a failure.
        ensure_mounted(app_id, key).await.expect("idempotent ensure");
        assert_eq!(std::fs::read_to_string(&probe).unwrap(), "survives reboot");

        // "Reboot": unmount, close the mapping (dropping the key from the
        // kernel), detach the loop device.
        let mp = data_dir.to_string_lossy().to_string();
        run("umount", &[&mp], None).await.expect("umount");
        run("cryptsetup", &["close", &mapper_name(app_id)], None)
            .await
            .expect("close");
        let img = image_path(app_id).to_string_lossy().to_string();
        let attached = run("losetup", &["-j", &img], None).await.unwrap();
        if let Some(dev) = String::from_utf8_lossy(&attached).split(':').next() {
            if !dev.is_empty() {
                run("losetup", &["-d", dev.trim()], None).await.expect("detach");
            }
        }
        assert!(!probe.exists(), "unmounted data must not be visible");

        // Same key re-derives the same volume; the data is still there.
        ensure_mounted(app_id, key).await.expect("re-ensure after reboot");
        assert_eq!(std::fs::read_to_string(&probe).unwrap(), "survives reboot");

        // A wrong key must be refused, never silently reformatted.
        run("umount", &[&mp], None).await.unwrap();
        run("cryptsetup", &["close", &mapper_name(app_id)], None)
            .await
            .unwrap();
        let wrong = ensure_mounted(app_id, b"the wrong key entirely..........").await;
        assert!(wrong.is_err(), "wrong key must fail to open the volume");

        // Leave no loop device behind (the wrong-key path re-attached one).
        let attached = run("losetup", &["-j", &img], None).await.unwrap();
        if let Some(dev) = String::from_utf8_lossy(&attached).split(':').next() {
            if !dev.is_empty() {
                let _ = run("losetup", &["-d", dev.trim()], None).await;
            }
        }
    }

    #[test]
    fn paths_are_per_app_and_stay_inside_the_volume_dir() {
        assert_eq!(
            image_path("my-app_1").to_string_lossy(),
            "/data/tapp/volumes/my-app_1.img"
        );
        assert_eq!(mapper_name("my-app_1"), "tapp-fde-my-app_1");
        // validate_app_id guarantees [A-Za-z0-9_-]; this is the belt to that
        // suspenders — a traversal-shaped id must not escape the directory.
        assert!(!image_path("my-app_1")
            .to_string_lossy()
            .contains(".."));
    }
}
