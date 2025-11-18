mod key_rotator;
mod validator;

use std::str::FromStr;

use actix_web::{App, HttpRequest, HttpResponse, HttpServer, get, http::header::HeaderName, web};

use crate::validator::validate_jwt;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let key_rotation_handle = key_rotator::rotate_keys_periodically();
    let server = HttpServer::new(|| App::new().service(verify))
        .bind(("127.0.0.1", 8080))?
        .run();

    tokio::select! {
        result = key_rotation_handle => {
            result?;
        },
        result = server => {
            result?;
        }
    }

    Ok(())
}

#[get("/verify/{aud}")]
async fn verify(aud: web::Path<String>, req: HttpRequest) -> HttpResponse {
    let header_name = HeaderName::from_str("Cf-Access-Jwt-Assertion").unwrap();
    let jwt_assertion: Option<&str> = req
        .headers()
        .get(&header_name)
        .and_then(|v| v.to_str().ok());

    let Some(jwt_assertion) = jwt_assertion else {
        return HttpResponse::Unauthorized().finish();
    };

    return if let Ok(data) = validate_jwt(&aud, &jwt_assertion).await {
        HttpResponse::Ok().json(data)
    } else {
        HttpResponse::Unauthorized().finish()
    };
}
