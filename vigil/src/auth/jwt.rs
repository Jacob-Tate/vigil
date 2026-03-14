use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};

use crate::{config::Config, error::AppError, types::AuthUser};

/// JWT claims — mirrors JwtPayload in server/src/types.ts.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Claims {
    pub sub: i64,       // user id
    pub username: String,
    pub role: String,
    pub iat: u64,
    pub exp: u64,
}

/// Sign a JWT for the given user.
pub fn sign_jwt(user: &AuthUser, config: &Config) -> Result<String, AppError> {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();

    let exp = now + config.session_duration_hours * 3600;

    let claims = Claims {
        sub: user.id,
        username: user.username.clone(),
        role: user.role.clone(),
        iat: now,
        exp,
    };

    encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(config.jwt_secret.as_bytes()),
    )
    .map_err(|e| AppError::Internal(format!("JWT sign error: {}", e)))
}

/// Verify a JWT and return its claims.
pub fn verify_jwt(token: &str, config: &Config) -> Result<Claims, AppError> {
    let mut validation = Validation::default();
    validation.validate_exp = true;

    decode::<Claims>(
        token,
        &DecodingKey::from_secret(config.jwt_secret.as_bytes()),
        &validation,
    )
    .map(|data| data.claims)
    .map_err(|e| {
        use jsonwebtoken::errors::ErrorKind;
        match e.kind() {
            ErrorKind::ExpiredSignature => AppError::Unauthorized("Session expired".into()),
            _ => AppError::Unauthorized("Invalid session".into()),
        }
    })
}
