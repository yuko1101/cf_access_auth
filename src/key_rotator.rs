use std::sync::{Arc, LazyLock};

use jsonwebtoken::DecodingKey;
use tokio::sync::Mutex;

const KEY_ROTATE_INTERVAL_SECS: u64 = 3600 * 24; // 24 hours

pub static TEAM_DOMAIN: LazyLock<String> =
    LazyLock::new(|| std::env::var("CF_TEAM_DOMAIN").expect("CF_TEAM_DOMAIN must be set"));
static REMOTE_JWKS_URL: LazyLock<String> =
    LazyLock::new(|| format!("{}/cdn-cgi/access/certs", TEAM_DOMAIN.as_str()));
pub static KEY: LazyLock<Arc<Mutex<Option<DecodingKey>>>> =
    LazyLock::new(|| Arc::new(Mutex::new(None)));

async fn fetch_jwks() -> anyhow::Result<DecodingKey> {
    let jwks_url = REMOTE_JWKS_URL.as_str();
    let resp = reqwest::get(jwks_url).await?;
    let jwks: serde_json::Value = resp.json().await?;
    let cert = jwks["public_cert"]["cert"]
        .as_str()
        .ok_or_else(|| anyhow::anyhow!("Failed to get cert from JWKS response: {:?}", jwks))?;

    let decoding_key = DecodingKey::from_rsa_pem(cert.as_bytes())?;
    println!("Fetched new JWKS from {}", jwks_url);
    Ok(decoding_key)
}

pub async fn rotate_keys_periodically() -> anyhow::Result<()> {
    let key_arc = KEY.clone();

    tokio::spawn(async move {
        loop {
            let new_key = match fetch_jwks().await {
                Ok(key) => key,
                Err(e) => {
                    eprintln!("Failed to fetch JWKS: {:?}", e);
                    continue;
                }
            };
            let mut key_lock = key_arc.lock().await;
            key_lock.replace(new_key);
            drop(key_lock);

            tokio::time::sleep(std::time::Duration::from_secs(KEY_ROTATE_INTERVAL_SECS)).await;
        }
    })
    .await?;

    Ok(())
}
