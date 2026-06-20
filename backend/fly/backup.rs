use base64;
use chrono;
use jsonwebtoken;
use reqwest;
use serde;
use serde_json;
use sqlx;
use std::time;
use tokio;
use tracing;

#[derive(serde::Serialize)]
struct GcsClaims {
    iss: String,
    scope: String,
    aud: String,
    exp: i64,
    iat: i64,
}

#[derive(serde::Deserialize)]
struct GcsTokenResponse {
    access_token: String,
}

#[derive(serde::Deserialize, Clone)]
struct ServiceAccountKey {
    client_email: String,
    private_key: String,
    token_uri: String,
}

pub fn spawn_gcs_backup_task(pool: sqlx::SqlitePool) {
    let bucket = std::env::var("GCS_BACKUP_BUCKET").ok();
    let key_base64 = std::env::var("GCS_SA_KEY_BASE64").ok();

    let (Some(bucket), Some(key_base64)) = (bucket, key_base64) else {
        tracing::info!(
            "GCS backup settings not fully configured (GCS_BACKUP_BUCKET and GCS_SA_KEY_BASE64). Skipping Tier 2 backup task."
        );
        return;
    };

    tokio::spawn(async move {
        // daily interval (24 hours)
        let mut ticker = tokio::time::interval(time::Duration::from_hours(24));
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

        // wait a few minutes after startup before running the first backup
        tokio::time::sleep(time::Duration::from_mins(5)).await;

        loop {
            ticker.tick().await;
            if let Err(err) = run_backup_and_upload(&pool, &bucket, &key_base64).await {
                tracing::error!(error = %err, "gcs_disaster_recovery_backup_failed");
            }
        }
    });
}

async fn run_backup_and_upload(
    pool: &sqlx::SqlitePool,
    bucket: &str,
    key_base64: &str,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // decode and parse GCS credentials
    let decoded_key = base64::Engine::decode(&base64::engine::general_purpose::STANDARD, key_base64.trim())?;
    let sa_key: ServiceAccountKey = serde_json::from_slice(&decoded_key)?;

    // generate point-in-time DB snapshot using SQLite's native VACUUM INTO
    let timestamp = chrono::Utc::now().timestamp();
    let tmp_path = format!("/tmp/backup-{timestamp}.db");

    tracing::info!(path = %tmp_path, "creating_database_snapshot");

    // sqlite's VACUUM INTO works on the database connection, creating a consistent snapshot copy
    // VACUUM INTO does not support bind parameters; tmp_path is safe since is derived from a timestamp
    sqlx::query(&format!("VACUUM INTO '{tmp_path}'")).execute(pool).await?;

    // obtain OAuth2 access token from Google Auth Server
    let token = get_gcs_access_token(&sa_key).await?;

    // upload snapshot to GCS
    let object_name = format!("db-snapshot-{}.sqlite", chrono::Utc::now().format("%Y-%m-%dT%H-%M-%SZ"));
    let client = reqwest::Client::new();
    let file_bytes = tokio::fs::read(&tmp_path).await?;

    tracing::info!(bucket = %bucket, file = %object_name, "uploading_snapshot_to_gcs");
    let upload_url =
        format!("https://storage.googleapis.com/upload/storage/v1/b/{bucket}/o?uploadType=media&name={object_name}");

    let res = client
        .post(&upload_url)
        .header("Authorization", format!("Bearer {token}"))
        .header("Content-Type", "application/x-sqlite3")
        .body(file_bytes)
        .send()
        .await?;

    // cleanup temp file
    tokio::fs::remove_file(&tmp_path).await.ok();

    let status = res.status();
    if !status.is_success() {
        let err_body = res.text().await.unwrap_or_default();
        return Err(format!("GCS upload failed with status {status}: {err_body}").into());
    }

    tracing::info!(file = %object_name, "snapshot_uploaded_successfully");
    Ok(())
}

async fn get_gcs_access_token(sa_key: &ServiceAccountKey) -> Result<String, Box<dyn std::error::Error + Send + Sync>> {
    let now = chrono::Utc::now().timestamp();
    let claims = GcsClaims {
        iss: sa_key.client_email.clone(),
        scope: "https://www.googleapis.com/auth/devstorage.read_write".to_string(),
        aud: sa_key.token_uri.clone(),
        exp: now + 3600,
        iat: now,
    };

    let header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::RS256);
    let key = jsonwebtoken::EncodingKey::from_rsa_pem(sa_key.private_key.as_bytes())?;
    let jwt = jsonwebtoken::encode(&header, &claims, &key)?;

    let client = reqwest::Client::new();
    let res = client
        .post(&sa_key.token_uri)
        .form(&[
            ("grant_type", "urn:ietf:params:oauth:grant-type:jwt-bearer"),
            ("assertion", &jwt),
        ])
        .send()
        .await?
        .json::<GcsTokenResponse>()
        .await?;

    Ok(res.access_token)
}
