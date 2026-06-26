use std::{
    collections::HashMap,
    sync::{Arc, LazyLock},
    time::{SystemTime, UNIX_EPOCH},
};

use anyhow::bail;
use jsonwebtoken::Validation;
use serde_json::Value;
use tokio::sync::Mutex;

use crate::key_rotator::{KEY, TEAM_DOMAIN};

#[derive(Clone, Debug)]
pub struct ClaimData {
    aud: String,
    exp: u64,
}

pub static CLAIM_CACHE: LazyLock<Arc<Mutex<HashMap<String, ClaimData>>>> =
    LazyLock::new(|| Arc::new(Mutex::new(HashMap::new())));

async fn validate_jwt(aud: &str, token: &str) -> anyhow::Result<Value> {
    let mut validation = Validation::new(jsonwebtoken::Algorithm::RS256);
    validation.set_audience(&[aud]);
    validation.set_issuer(&[TEAM_DOMAIN.as_str()]);
    validation.set_required_spec_claims(&["aud", "iss", "exp"]);

    let key = KEY.lock().await;
    let Some(jwks_data) = &*key else {
        bail!("Decoding key is not available");
    };
    let json = jsonwebtoken::decode::<Value>(token, jwks_data.get_key()?, &validation);

    return match json {
        Ok(data) => Ok(data.claims),
        Err(e) => {
            bail!("JWT validation failed: {:?}", e);
        }
    };
}

pub async fn validate_jwt_with_cache(aud: &str, token: &str) -> anyhow::Result<ClaimData> {
    if let Some(cached) = CLAIM_CACHE.lock().await.get(token) {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|e| anyhow::anyhow!("System time error: {:?}", e))?
            .as_secs();
        if cached.exp > now && cached.aud == aud {
            return Ok(cached.clone());
        }
    }

    let claims = validate_jwt(aud, token).await?;

    let exp = claims
        .get("exp")
        .and_then(|v| {
            v.as_u64()
                .or_else(|| v.as_i64().and_then(|n| u64::try_from(n).ok()))
        })
        .ok_or_else(|| anyhow::anyhow!("JWT exp claim is missing or invalid"))?;

    let claim_data = ClaimData {
        aud: aud.to_string(),
        exp,
    };
    CLAIM_CACHE
        .lock()
        .await
        .insert(token.to_string(), claim_data.clone());
    Ok(claim_data)
}
