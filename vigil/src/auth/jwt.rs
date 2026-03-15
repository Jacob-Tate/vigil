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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{config::Config, types::AuthUser};

    fn test_config() -> Config {
        Config {
            port: 3001,
            jwt_secret: "test-secret-key-for-unit-tests-long-enough".to_string(),
            notifications_encryption_key: None,
            admin_username: "admin".to_string(),
            admin_password: "password".to_string(),
            session_duration_hours: 8,
            client_origin: "http://localhost:5173".to_string(),
            base_url: "http://localhost:5173".to_string(),
            alert_cooldown_seconds: 3600,
            nvd_sync_interval_hours: 2,
            kev_sync_interval_hours: 24,
            vulnrichment_sync_interval_hours: 24,
            cvelist_sync_interval_hours: 24,
            diff_retention_days: 30,
            data_dir: "data".to_string(),
            is_production: false,
        }
    }

    fn test_user() -> AuthUser {
        AuthUser {
            id: 42,
            username: "testuser".to_string(),
            role: "viewer".to_string(),
        }
    }

    #[test]
    fn sign_and_verify_roundtrip() {
        let config = test_config();
        let user = test_user();
        let token = sign_jwt(&user, &config).unwrap();
        let claims = verify_jwt(&token, &config).unwrap();
        assert_eq!(claims.sub, user.id);
        assert_eq!(claims.username, user.username);
        assert_eq!(claims.role, user.role);
    }

    #[test]
    fn wrong_secret_fails_verification() {
        let config = test_config();
        let token = sign_jwt(&test_user(), &config).unwrap();
        let mut other = config.clone();
        other.jwt_secret = "completely-different-secret".to_string();
        let result = verify_jwt(&token, &other);
        assert!(matches!(result, Err(AppError::Unauthorized(_))));
    }

    #[test]
    fn tampered_signature_fails() {
        let config = test_config();
        let token = sign_jwt(&test_user(), &config).unwrap();
        let tampered = format!("{}XXX", token);
        let result = verify_jwt(&tampered, &config);
        assert!(matches!(result, Err(AppError::Unauthorized(_))));
    }

    #[test]
    fn expired_token_returns_session_expired_message() {
        use jsonwebtoken::{encode, EncodingKey, Header};
        let config = test_config();
        // exp set to UNIX epoch + 1 — well in the past
        let claims = Claims {
            sub: 1,
            username: "test".to_string(),
            role: "viewer".to_string(),
            iat: 1,
            exp: 2,
        };
        let token = encode(
            &Header::default(),
            &claims,
            &EncodingKey::from_secret(config.jwt_secret.as_bytes()),
        )
        .unwrap();
        match verify_jwt(&token, &config) {
            Err(AppError::Unauthorized(msg)) => assert_eq!(msg, "Session expired"),
            other => panic!("expected Unauthorized('Session expired'), got {:?}", other),
        }
    }

    #[test]
    fn admin_role_preserved_in_claims() {
        let config = test_config();
        let admin = AuthUser {
            id: 1,
            username: "admin".to_string(),
            role: "admin".to_string(),
        };
        let token = sign_jwt(&admin, &config).unwrap();
        let claims = verify_jwt(&token, &config).unwrap();
        assert_eq!(claims.role, "admin");
    }
}
