use ed25519_dalek::{SigningKey, pkcs8::EncodePrivateKey};
use jsonwebtoken::{
    Algorithm, DecodingKey, EncodingKey, Validation, decode, encode, get_current_timestamp,
};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Claims {
    pub sub: String,
    pub exp: u64,
}

#[derive(Clone)]
pub struct JwtService {
    encoding_key: EncodingKey,
    decoding_key: DecodingKey,
}

impl JwtService {
    const EXPIRE_IN: u64 = 3600;
    const SUB: &str = "trivy-operator-web-ui";

    pub fn new() -> JwtService {
        let mut csprng = OsRng;
        let signing_key: SigningKey = SigningKey::generate(&mut csprng);

        let pkcs8 = signing_key.to_pkcs8_der().unwrap();
        let pkcs8 = pkcs8.as_bytes();
        let encoding_key = EncodingKey::from_ed_der(pkcs8);

        let verifying_key = signing_key.verifying_key();
        let public_key = verifying_key.as_bytes();
        let decoding_key = DecodingKey::from_ed_der(public_key);

        JwtService {
            encoding_key,
            decoding_key,
        }
    }

    pub fn generate(&self) -> String {
        let claims = Claims {
            sub: Self::SUB.to_string(),
            exp: get_current_timestamp() + Self::EXPIRE_IN,
        };

        encode(
            &jsonwebtoken::Header::new(Algorithm::EdDSA),
            &claims,
            &self.encoding_key,
        )
        .unwrap()
    }

    pub fn verify(&self, token: &[u8]) -> bool {
        let validation = Validation::new(Algorithm::EdDSA);
        let _token_data = decode::<Claims>(token, &self.decoding_key, &validation);

        _token_data.is_ok() && _token_data.unwrap().claims.exp > get_current_timestamp()
    }
}

#[cfg(test)]
mod tests {
    use anyhow::Result;
    use jsonwebtoken::{Algorithm, encode, get_current_timestamp};

    use crate::api::services::{JwtService, jwt::Claims};

    impl JwtService {
        pub fn generate_expired(&self) -> String {
            let claims = Claims {
                sub: "trivy-operator-web-ui".to_string(),
                exp: get_current_timestamp() - 10,
            };

            let token = encode(
                &jsonwebtoken::Header::new(Algorithm::EdDSA),
                &claims,
                &self.encoding_key,
            )
            .unwrap();

            token
        }
    }

    #[test]
    fn valid_token() -> Result<()> {
        let jwt_service = JwtService::new();

        let token = jwt_service.generate();

        assert!(jwt_service.verify(token.as_bytes()));

        Ok(())
    }

    #[test]
    fn not_valid_token() -> Result<()> {
        let jwt_service = JwtService::new();
        let other_jwt_service = JwtService::new();

        let other_token = other_jwt_service.generate();
        let dummy_token = "dummy";

        assert!(!jwt_service.verify(other_token.as_bytes()));
        assert!(!jwt_service.verify(dummy_token.as_bytes()));

        Ok(())
    }

    #[test]
    fn expired_token() -> Result<()> {
        let jwt_service = JwtService::new();

        let token = jwt_service.generate_expired();

        assert!(!jwt_service.verify(token.as_bytes()));

        Ok(())
    }
}
