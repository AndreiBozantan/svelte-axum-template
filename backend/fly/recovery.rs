use std::os::unix::fs::MetadataExt;

use tracing;

const VOLUME_MOUNT: &str = "/data";

/// Checks whether the data volume is properly mounted and writable.
///
/// If the volume is missing or broken, logs a critical error and exits with a non-zero code.
/// This prevents silent data loss by running on the ephemeral root disk.
///
/// This is a no-op when not running on Fly.io (`FLY_APP_NAME` not set).
/// Must be called early in startup, before database initialization.
pub fn check_volume_and_self_heal() {
    let Ok(_app_name) = std::env::var("FLY_APP_NAME") else {
        tracing::debug!("not_running_on_fly_skipping_volume_check");
        return;
    };

    if is_volume_healthy() {
        tracing::info!(mount = VOLUME_MOUNT, "volume_mount_healthy");
        return;
    }

    tracing::error!(mount = VOLUME_MOUNT, "volume_not_mounted_or_unhealthy_aborting_startup");

    // exit non-zero so Fly's restart policy retries and alerts the operator
    std::process::exit(1);
}

/// Determines whether `/data` is a real mounted volume (not just an empty directory
/// on the container's ephemeral root filesystem) and is writable.
///
/// A missing Fly volume mount still leaves `/data` as a writable directory on the root
/// filesystem, so a simple write test is not sufficient. We compare device IDs of `/data`
/// and `/` — if they match, `/data` sits on the root filesystem (no volume attached).
fn is_volume_healthy() -> bool {
    let Ok(volume_meta) = std::fs::metadata(VOLUME_MOUNT) else {
        return false;
    };

    let Ok(root_meta) = std::fs::metadata("/") else {
        return false;
    };

    // same device ID means /data is on the root filesystem — no volume is mounted
    if volume_meta.dev() == root_meta.dev() {
        tracing::warn!(
            volume_dev = volume_meta.dev(),
            root_dev = root_meta.dev(),
            "volume_shares_device_with_root_filesystem"
        );
        return false;
    }

    // confirm the mount is writable
    let healthcheck_path = format!("{VOLUME_MOUNT}/.healthcheck");
    if std::fs::write(&healthcheck_path, b"ok").is_err() {
        tracing::warn!("volume_mount_not_writable");
        return false;
    }
    let _ = std::fs::remove_file(&healthcheck_path);

    true
}
