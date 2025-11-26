use std::sync::{Arc, LazyLock};

use anyhow::bail;
use jsonwebtoken::DecodingKey;
use tokio::sync::Mutex;

const KEY_ROTATE_INTERVAL_SECS: u64 = 3600 * 24; // 24 hours
const KEY_EXPIRY_SECS: u64 = 3600 * 24 * 3; // 3 days

pub static TEAM_DOMAIN: LazyLock<String> =
    LazyLock::new(|| std::env::var("CF_TEAM_DOMAIN").expect("CF_TEAM_DOMAIN must be set"));
static REMOTE_JWKS_URL: LazyLock<String> =
    LazyLock::new(|| format!("{}/cdn-cgi/access/certs", TEAM_DOMAIN.as_str()));
pub static KEY: LazyLock<Arc<Mutex<Option<JwksData>>>> =
    LazyLock::new(|| Arc::new(Mutex::new(None)));

pub struct JwksData {
    key: DecodingKey,
    fetched_at: std::time::Instant,
}

impl JwksData {
    fn is_expired(&self) -> bool {
        self.fetched_at.elapsed().as_secs() >= KEY_EXPIRY_SECS
    }

    pub fn get_key(&self) -> anyhow::Result<&DecodingKey> {
        if self.is_expired() {
            bail!("JWKS key is expired");
        }
        Ok(&self.key)
    }
}

async fn fetch_jwks() -> anyhow::Result<JwksData> {
    let jwks_url = REMOTE_JWKS_URL.as_str();
    let resp = reqwest::get(jwks_url).await?;
    let jwks: serde_json::Value = resp.json().await?;
    let cert = jwks["public_cert"]["cert"]
        .as_str()
        .ok_or_else(|| anyhow::anyhow!("Failed to get cert from JWKS response: {:?}", jwks))?;

    let decoding_key = DecodingKey::from_rsa_pem(cert.as_bytes())?;
    let jwks_data = JwksData {
        key: decoding_key,
        fetched_at: std::time::Instant::now(),
    };
    println!("Fetched new JWKS from {}", jwks_url);
    Ok(jwks_data)
}

pub async fn rotate_keys_periodically() -> anyhow::Result<()> {
    let key_arc = KEY.clone();

    tokio::spawn(async move {
        loop {
            let new_key = match fetch_jwks().await {
                Ok(key) => key,
                Err(e) => {
                    // TODO: Consider adding retry logic
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
