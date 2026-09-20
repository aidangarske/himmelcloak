/*
 * Himmelcloak native Keycloak authentication
 * SPDX-License-Identifier: LGPL-3.0-or-later OR GPL-3.0-or-later
 */
use std::path::PathBuf;
use std::time::Duration;

use url::{Host, Url};

use crate::error::{Error, Result};

/// Runtime settings for a public Keycloak client.
#[derive(Clone)]
pub struct Config {
    pub server_url: Url,
    pub realm: String,
    pub client_id: String,
    pub redirect_uri: Url,
    pub ca_bundle: Option<PathBuf>,
    pub timeout: Duration,
}

impl Config {
    pub fn new(server_url: &str, realm: &str, client_id: &str) -> Result<Self> {
        let server_url =
            Url::parse(server_url).map_err(|_| Error::InvalidConfiguration("server URL"))?;
        let config = Self {
            server_url,
            realm: realm.to_owned(),
            client_id: client_id.to_owned(),
            redirect_uri: Url::parse("http://127.0.0.1:8845/himmelcloak/callback")
                .expect("constant URL"),
            ca_bundle: None,
            timeout: Duration::from_secs(15),
        };
        config.validate()?;
        Ok(config)
    }

    pub(crate) fn validate(&self) -> Result<()> {
        let loopback = match self.server_url.host() {
            Some(Host::Domain("localhost")) => true,
            Some(Host::Ipv4(address)) => address.is_loopback(),
            Some(Host::Ipv6(address)) => address.is_loopback(),
            _ => false,
        };
        if self.server_url.scheme() != "https" && !(self.server_url.scheme() == "http" && loopback)
        {
            return Err(Error::InvalidConfiguration(
                "Keycloak requires HTTPS outside loopback",
            ));
        }
        if self.server_url.query().is_some()
            || self.server_url.fragment().is_some()
            || !self.server_url.username().is_empty()
            || self.server_url.password().is_some()
        {
            return Err(Error::InvalidConfiguration(
                "server URL must not have credentials, query, or fragment",
            ));
        }
        if self.realm.is_empty() || self.realm.contains('/') || self.client_id.is_empty() {
            return Err(Error::InvalidConfiguration("realm or client ID"));
        }
        if self.timeout.is_zero() {
            return Err(Error::InvalidConfiguration("timeout must be positive"));
        }
        Ok(())
    }

    pub(crate) fn issuer(&self) -> Result<Url> {
        let mut url = self.server_url.clone();
        url.path_segments_mut()
            .map_err(|_| Error::InvalidConfiguration("server URL cannot be a base"))?
            .pop_if_empty()
            .push("realms")
            .push(&self.realm);
        Ok(url)
    }
}

#[cfg(test)]
mod tests {
    use super::Config;
    use url::Url;

    #[test]
    fn rejects_credentials_embedded_in_server_url() {
        assert!(Config::new("https://user:secret@keycloak.example", "test", "client").is_err());
    }

    #[test]
    fn revalidates_public_config_fields_before_use() {
        let mut config = Config::new("https://keycloak.example", "test", "client").unwrap();
        config.server_url = Url::parse("http://remote.example").unwrap();
        assert!(config.validate().is_err());
    }

    #[test]
    fn allows_ipv6_loopback_but_rejects_remote_http() {
        assert!(Config::new("http://[::1]:8443", "test", "client").is_ok());
        assert!(Config::new("http://[2001:db8::1]:8443", "test", "client").is_err());
    }
}
