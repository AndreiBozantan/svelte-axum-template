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
