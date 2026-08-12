use std::time::Duration;

use anyhow::{Context, Result};
use iroh::endpoint::presets::Preset;
use iroh::{RelayMap, RelayMode, RelayUrl, SecretKey};
use iroh_services::caps::{Cap, Caps, RelayCap};
use iroh_services::{ApiSecret, API_SECRET_ENV_VAR_NAME};

const RELAYS: [&str; 4] = [
    "https://e67jyfby7vj7ak9h9.euc1.relay.iroh-svc.com/",
    "https://e67jyfby7vj7ak9h9.use1.relay.iroh-svc.com/",
    "https://e67jyfby7vj7ak9h9.usw1.relay.iroh-svc.com/",
    "https://e67jyfby7vj7ak9h9.aps1.relay.iroh-svc.com/",
];

const RELAY_TOKEN_LIFETIME: Duration = Duration::from_secs(30 * 24 * 60 * 60);

/// The server-side key that grants relay access to one endpoint.
pub struct RelayIssuer {
    api_secret: ApiSecret,
}

impl RelayIssuer {
    /// Load the Iroh Services API secret from its standard environment variable.
    pub fn from_env() -> Result<Self> {
        let api_secret = ApiSecret::from_env_var(API_SECRET_ENV_VAR_NAME)
            .context("reading IROH_SERVICES_API_SECRET")?;
        Ok(Self { api_secret })
    }

    /// Make a relay-only token for one endpoint.
    pub fn token(&self, endpoint_key: &[u8; 32]) -> Result<String> {
        let endpoint_id = iroh::EndpointId::from_bytes(endpoint_key)
            .context("the relay endpoint key is invalid")?;
        let token = iroh_services::caps::create_api_token_from_secret_key(
            self.api_secret.secret.clone(),
            endpoint_id,
            RELAY_TOKEN_LIFETIME,
            Caps::new([Cap::Relay(RelayCap::Use)]),
        )?;
        let mut encoded = data_encoding::BASE32_NOPAD.encode(&token.encode());
        encoded.make_ascii_lowercase();
        Ok(encoded)
    }
}

/// The endpoint preset for the dev.site relay network.
pub struct DevsitePreset {
    secret_key: SecretKey,
    relays: RelayMap,
}

impl Preset for DevsitePreset {
    fn apply(self, builder: iroh::endpoint::Builder) -> iroh::endpoint::Builder {
        let builder = iroh::endpoint::presets::N0.apply(builder);
        builder
            .relay_mode(RelayMode::Custom(self.relays))
            .secret_key(self.secret_key)
    }
}

/// Make the Iroh preset for the dev.site relay network.
pub fn preset(secret_key: SecretKey, relay_token: impl Into<String>) -> Result<DevsitePreset> {
    let relays = RELAYS
        .into_iter()
        .map(|url| {
            url.parse::<RelayUrl>()
                .with_context(|| format!("invalid dev.site relay URL {url}"))
        })
        .collect::<Result<Vec<_>>>()?;
    let relays = RelayMap::from_iter(relays).with_auth_token(relay_token);
    Ok(DevsitePreset { secret_key, relays })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn relay_tokens_are_scoped_to_endpoint_keys() {
        let api_secret = ApiSecret::new(SecretKey::generate(), SecretKey::generate().public());
        let issuer = RelayIssuer { api_secret };
        let first = SecretKey::generate().public();
        let second = SecretKey::generate().public();

        let first_token = issuer.token(first.as_bytes()).unwrap();
        let second_token = issuer.token(second.as_bytes()).unwrap();

        assert_ne!(first_token, second_token);
        assert!(first_token
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit()));
    }
}
