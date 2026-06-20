use std::path;
use std::process;
use std::sync;
use tracing;

static LITESTREAM_PROCESS: sync::Mutex<Option<process::Child>> = sync::Mutex::new(None);

pub fn init_litestream(db_path: &str) {
    let litestream_path = path::Path::new("/usr/local/bin/litestream");
    if !litestream_path.exists() {
        tracing::info!("Litestream binary not found at /usr/local/bin/litestream. Skipping replication setup.");
        return;
    }

    // restore database if it does not exist
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
