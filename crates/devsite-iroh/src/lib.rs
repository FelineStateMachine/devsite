use std::str::FromStr;
use std::time::Duration;

use anyhow::{Context, Result};
use iroh::endpoint::presets::Preset;
use iroh::{RelayMap, RelayMode, RelayUrl, SecretKey};
use iroh_services::caps::{Cap, Caps, RelayCap};
use iroh_services::{ApiSecret, API_SECRET_ENV_VAR_NAME};
use serde::{Deserialize, Serialize};

pub const RELAY_URLS_ENV_VAR_NAME: &str = "DEVSITE_RELAY_URLS";

const RELAY_TOKEN_LIFETIME: Duration = Duration::from_secs(30 * 24 * 60 * 60);

/// The relay settings that the control plane gives to an endpoint.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct RelayAccess {
    /// The endpoint-scoped Iroh Services token, when the server has an API secret.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub relay_token: Option<String>,
    /// Custom relay URLs. An empty list selects the n0 relay preset.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub relay_urls: Vec<String>,
}

/// The control-plane relay configuration.
pub struct RelayConfig {
    api_secret: Option<ApiSecret>,
    relay_urls: Vec<RelayUrl>,
}

impl RelayConfig {
    /// Load the optional Iroh Services key and custom relay URLs.
    pub fn from_env() -> Result<Self> {
        let api_secret = if std::env::var_os(API_SECRET_ENV_VAR_NAME).is_some() {
            Some(
                ApiSecret::from_env_var(API_SECRET_ENV_VAR_NAME)
                    .context("reading IROH_SERVICES_API_SECRET")?,
            )
        } else {
            None
        };
        let relay_urls = std::env::var(RELAY_URLS_ENV_VAR_NAME)
            .ok()
            .map(|value| parse_relay_urls(&value))
            .transpose()?
            .unwrap_or_default();
        Ok(Self {
            api_secret,
            relay_urls,
        })
    }

    /// Make the relay settings for one endpoint.
    pub fn access(&self, endpoint_key: &[u8; 32]) -> Result<RelayAccess> {
        let relay_token = self
            .api_secret
            .as_ref()
            .map(|api_secret| relay_token(api_secret, endpoint_key))
            .transpose()?;
        let relay_urls = self.relay_urls.iter().map(ToString::to_string).collect();
        Ok(RelayAccess {
            relay_token,
            relay_urls,
        })
    }
}

fn parse_relay_urls(value: &str) -> Result<Vec<RelayUrl>> {
    value
        .split(',')
        .map(str::trim)
        .filter(|url| !url.is_empty())
        .map(|url| {
            RelayUrl::from_str(url)
                .with_context(|| format!("invalid relay URL in {RELAY_URLS_ENV_VAR_NAME}: {url}"))
        })
        .collect()
}

fn relay_token(api_secret: &ApiSecret, endpoint_key: &[u8; 32]) -> Result<String> {
    let endpoint_id =
        iroh::EndpointId::from_bytes(endpoint_key).context("the relay endpoint key is invalid")?;
    let token = iroh_services::caps::create_api_token_from_secret_key(
        api_secret.secret.clone(),
        endpoint_id,
        RELAY_TOKEN_LIFETIME,
        Caps::new([Cap::Relay(RelayCap::Use)]),
    )?;
    let mut encoded = data_encoding::BASE32_NOPAD.encode(&token.encode());
    encoded.make_ascii_lowercase();
    Ok(encoded)
}

/// The endpoint preset for the configured relay network.
pub struct DevsitePreset {
    secret_key: SecretKey,
    relay_mode: Option<RelayMode>,
}

impl Preset for DevsitePreset {
    fn apply(self, builder: iroh::endpoint::Builder) -> iroh::endpoint::Builder {
        let builder = iroh::endpoint::presets::N0.apply(builder);
        let builder = match self.relay_mode {
            Some(relay_mode) => builder.relay_mode(relay_mode),
            None => builder,
        };
        builder.secret_key(self.secret_key)
    }
}

/// Make an Iroh preset from relay settings supplied by the control plane.
pub fn preset(secret_key: SecretKey, access: RelayAccess) -> Result<DevsitePreset> {
    let relay_mode = relay_mode(&access)?;
    Ok(DevsitePreset {
        secret_key,
        relay_mode,
    })
}

fn relay_mode(access: &RelayAccess) -> Result<Option<RelayMode>> {
    if access.relay_urls.is_empty() && access.relay_token.is_none() {
        return Ok(None);
    }

    let relays = if access.relay_urls.is_empty() {
        iroh::endpoint::default_relay_mode().relay_map()
    } else {
        RelayMap::from_iter(
            access
                .relay_urls
                .iter()
                .map(|url| {
                    url.parse::<RelayUrl>()
                        .with_context(|| format!("invalid relay URL from the control plane: {url}"))
                })
                .collect::<Result<Vec<_>>>()?,
        )
    };
    let relays = match &access.relay_token {
        Some(token) => relays.with_auth_token(token.clone()),
        None => relays,
    };
    Ok(Some(RelayMode::Custom(relays)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn relay_tokens_are_scoped_to_endpoint_keys() {
        let api_secret = ApiSecret::new(SecretKey::generate(), SecretKey::generate().public());
        let first = SecretKey::generate().public();
        let second = SecretKey::generate().public();

        let first_token = relay_token(&api_secret, first.as_bytes()).unwrap();
        let second_token = relay_token(&api_secret, second.as_bytes()).unwrap();

        assert_ne!(first_token, second_token);
        assert!(first_token
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit()));
    }

    #[test]
    fn relay_urls_are_configured_as_a_comma_separated_list() {
        let urls =
            parse_relay_urls("https://use1.example.test/, https://euc1.example.test/").unwrap();

        assert_eq!(urls.len(), 2);
        assert_eq!(urls[0].to_string(), "https://use1.example.test/");
        assert_eq!(urls[1].to_string(), "https://euc1.example.test/");
    }

    #[test]
    fn empty_access_keeps_the_n0_preset() {
        assert!(relay_mode(&RelayAccess::default()).unwrap().is_none());
    }

    #[test]
    fn a_token_uses_the_n0_relay_map_when_urls_are_not_configured() {
        let access = RelayAccess {
            relay_token: Some("token".to_string()),
            relay_urls: Vec::new(),
        };

        assert!(matches!(
            relay_mode(&access).unwrap(),
            Some(RelayMode::Custom(_))
        ));
    }

    #[test]
    fn invalid_custom_relay_urls_fail_before_binding() {
        let access = RelayAccess {
            relay_token: None,
            relay_urls: vec!["not a URL".to_string()],
        };

        assert!(relay_mode(&access).is_err());
    }
}
