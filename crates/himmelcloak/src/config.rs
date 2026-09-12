// SPDX-License-Identifier: LGPL-3.0-or-later OR GPL-3.0-or-later
//! Runtime configuration (issuer, realm, client id, timeouts, TLS trust).

#[derive(Default, Clone)]
pub struct Config {
    pub issuer: String,
    pub realm: String,
    pub client_id: String,
}
