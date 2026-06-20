use std::path;
use std::process;
use std::sync;
use tracing;

const VOLUME_MOUNT: &str = "/data";
static LITESTREAM_PROCESS: sync::Mutex<Option<process::Child>> = sync::Mutex::new(None);

pub fn init(db_path: &str) {
    let Ok(_) = std::env::var("FLY_APP_NAME") else {
        tracing::debug!("not_running_on_fly_skipping_volume_check");
        return;
    };

    if !is_volume_healthy() {
        // exit non-zero so Fly's restart policy retries and alerts the operator
        tracing::error!(mount = VOLUME_MOUNT, "volume_not_mounted_or_unhealthy_aborting_startup");
        std::process::exit(1);
    }

    tracing::info!(mount = VOLUME_MOUNT, "volume_mount_healthy");

    let litestream_path = path::Path::new("/usr/local/bin/litestream");
    if !litestream_path.exists() {
        tracing::info!("Litestream binary not found at /usr/local/bin/litestream. Skipping replication setup.");
        return;
    }

    // restore database if it does not exist
    let db_path = db_path.strip_prefix("sqlite:").unwrap_or(db_path);
    let db_file_path = path::Path::new(db_path);
    if !db_file_path.exists() {
        tracing::info!(path = %db_path, "database_file_not_found_attempting_litestream_restore");

        let status = match process::Command::new(litestream_path)
            .args(["restore", "-if-replica-exists", db_path])
            .status()
        {
            Ok(status) => status,
            Err(err) => {
                tracing::error!(error = %err, "failed_to_execute_litestream_restore");
                return;
            },
        };

        if status.success() {
            tracing::info!("litestream_restore_completed_successfully");
        } else {
            tracing::error!(status = ?status.code(), "litestream_restore_failed_with_non_zero_status");
        }
    }

    // start litestream replicate in the background
    tracing::info!("starting_litestream_replication_subprocess");
    let child = match process::Command::new(litestream_path).args(["replicate"]).spawn() {
        Ok(child) => child,
        Err(err) => {
            tracing::error!(error = %err, "failed_to_spawn_litestream_replication");
            return;
        },
    };

    if let Ok(mut guard) = LITESTREAM_PROCESS.lock() {
        *guard = Some(child);
    }
}

pub fn stop_litestream() {
    if let Some(mut child) = LITESTREAM_PROCESS.lock().ok().and_then(|mut guard| guard.take()) {
        tracing::info!("terminating_litestream_replication_subprocess");
        let _ = child.kill();
        let _ = child.wait();
    }
}

/// Checks if the Litestream replication subprocess is still running.
///
/// Returns true if it is running normally, or if Litestream is not enabled/found.
/// Returns false if the process has exited unexpectedly or if an error occurred.
pub fn is_litestream_healthy() -> bool {
    let litestream_path = path::Path::new("/usr/local/bin/litestream");
    if !litestream_path.exists() {
        return true;
    }

    let Ok(mut guard) = LITESTREAM_PROCESS.lock() else {
        tracing::error!("litestream_process_mutex_poisoned");
        return false;
    };

    let Some(child) = guard.as_mut() else {
        tracing::error!("litestream_replicate_subprocess_not_started");
        return false;
    };

    let status = child.try_wait();
    drop(guard);

    match status {
        Ok(None) => true,
        Ok(Some(exit_status)) => {
            tracing::error!(status = ?exit_status.code(), "litestream_replicate_subprocess_exited_unexpectedly");
            false
        },
        Err(err) => {
            tracing::error!(error = %err, "failed_to_query_litestream_subprocess_status");
            false
        },
    }
}

/// Determines whether `/data` is a real mounted volume (not just an empty directory
/// on the container's ephemeral root filesystem) and is writable.
///
/// A missing Fly volume mount still leaves `/data` as a writable directory on the root
/// filesystem, so a simple write test is not sufficient. We compare device IDs of `/data`
/// and `/` — if they match, `/data` sits on the root filesystem (no volume attached).
fn is_volume_healthy() -> bool {
    use std::os::unix::fs::MetadataExt;

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
