use std::os::unix::fs::MetadataExt;

use reqwest;
use serde_json;
use tracing;

const VOLUME_MOUNT: &str = "/data";
const FLY_MACHINES_API: &str = "https://api.machines.dev/v1";

/// Checks whether the data volume is properly mounted and writable.
///
/// If the volume is missing or broken, triggers self-replacement via the Fly Machines API:
/// creates a new volume, spins up a replacement machine with the new volume attached,
/// then destroys the current machine.
///
/// This is a no-op when not running on Fly.io (`FLY_APP_NAME` not set).
/// Must be called early in startup, before database initialization.
pub async fn check_volume_and_self_heal() {
    let Ok(app_name) = std::env::var("FLY_APP_NAME") else {
        tracing::debug!("not_running_on_fly_skipping_volume_check");
        return;
    };

    if is_volume_healthy() {
        tracing::info!(mount = VOLUME_MOUNT, "volume_mount_healthy");
        return;
    }

    tracing::warn!(
        mount = VOLUME_MOUNT,
        "volume_not_mounted_or_unhealthy_triggering_self_replacement"
    );

    if let Err(err) = trigger_self_replacement(&app_name).await {
        tracing::error!(error = %err, "self_replacement_failed");
        // exit non-zero so Fly's restart policy retries the whole entrypoint
        std::process::exit(1);
    }

    // exit cleanly — replacement machine is being created, this one is being destroyed
    std::process::exit(0);
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

async fn trigger_self_replacement(app_name: &str) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let api_token = std::env::var("FLY_API_TOKEN")
        .map_err(|_| "FLY_API_TOKEN not set — cannot call Machines API for self-replacement")?;
    let region = std::env::var("FLY_REGION").map_err(|_| "FLY_REGION not set")?;
    let machine_id = std::env::var("FLY_MACHINE_ID").map_err(|_| "FLY_MACHINE_ID not set")?;
    let image_ref = std::env::var("FLY_IMAGE_REF").map_err(|_| "FLY_IMAGE_REF not set")?;

    let client = reqwest::Client::new();
    let auth_header = format!("Bearer {api_token}");

    // create a replacement volume
    tracing::info!(app = app_name, region = %region, "creating_replacement_volume");

    let volume_res = client
        .post(format!("{FLY_MACHINES_API}/apps/{app_name}/volumes"))
        .header("Authorization", &auth_header)
        .json(&serde_json::json!({
            "name": "svelaxum_data",
            "region": region,
            "size_gb": 3
        }))
        .send()
        .await?;

    if !volume_res.status().is_success() {
        let status = volume_res.status();
        let body = volume_res.text().await.unwrap_or_default();
        return Err(format!("volume creation failed ({status}): {body}").into());
    }

    let volume_data: serde_json::Value = volume_res.json().await?;
    let volume_id = volume_data["id"]
        .as_str()
        .ok_or("missing volume id in Machines API response")?;

    tracing::info!(volume_id = volume_id, "replacement_volume_created");

    // create a replacement machine with the new volume
    tracing::info!("creating_replacement_machine");

    let machine_res = client
        .post(format!("{FLY_MACHINES_API}/apps/{app_name}/machines"))
        .header("Authorization", &auth_header)
        .json(&serde_json::json!({
            "region": region,
            "config": {
                "image": image_ref,
                "mounts": [{ "volume": volume_id, "path": "/data" }],
                "services": [{
                    "protocol": "tcp",
                    "internal_port": 3000,
                    "ports": [
                        { "port": 443, "handlers": ["tls", "http"] },
                        { "port": 80, "handlers": ["http"] }
                    ]
                }],
                "checks": {
                    "health": {
                        "type": "http",
                        "port": 3000,
                        "path": "/api/health",
                        "interval": "30s",
                        "timeout": "5s"
                    }
                }
            }
        }))
        .send()
        .await?;

    if !machine_res.status().is_success() {
        let status = machine_res.status();
        let body = machine_res.text().await.unwrap_or_default();
        return Err(format!("machine creation failed ({status}): {body}").into());
    }

    tracing::info!("replacement_machine_created");

    // destroy the current (broken) machine
    tracing::info!(machine_id = %machine_id, "destroying_current_machine");

    let destroy_res = client
        .delete(format!("{FLY_MACHINES_API}/apps/{app_name}/machines/{machine_id}"))
        .header("Authorization", &auth_header)
        .send()
        .await?;

    if !destroy_res.status().is_success() {
        let status = destroy_res.status();
        let body = destroy_res.text().await.unwrap_or_default();
        // non-fatal: the replacement is already created. Worst case we have an extra machine
        // that will fail the same check and exit on its own.
        tracing::warn!(status = %status, body = %body, "machine_self_destroy_request_failed");
    }

    tracing::info!("self_replacement_complete");
    Ok(())
}
