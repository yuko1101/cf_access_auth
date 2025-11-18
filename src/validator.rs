use anyhow::bail;
use jsonwebtoken::Validation;
use serde_json::Value;

use crate::key_rotator::{KEY, TEAM_DOMAIN};

pub async fn validate_jwt(aud: &str, token: &str) -> anyhow::Result<Value> {
    let mut validation = Validation::new(jsonwebtoken::Algorithm::RS256);
    validation.set_audience(&[aud]);
    validation.set_issuer(&[TEAM_DOMAIN.as_str()]);
    validation.set_required_spec_claims(&["aud", "iss", "exp"]);

    let key = KEY.lock().await;
    let Some(key) = &*key else {
        bail!("Decoding key is not available");
    };
    let json = jsonwebtoken::decode::<Value>(token, key, &validation);

    return match json {
        Ok(data) => Ok(data.claims),
        Err(e) => {
            bail!("JWT validation failed: {:?}", e);
        }
    };
}
