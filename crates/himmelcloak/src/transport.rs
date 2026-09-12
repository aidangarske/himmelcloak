// SPDX-License-Identifier: LGPL-3.0-or-later OR GPL-3.0-or-later
//! HTTP transport: a trait + a TLS-backed client, mockable for offline fixture tests.
//!
//! TLS is wolfSSL (all-wolf policy). Integration route to settle in the spike: rustls +
//! `rustls-wolfcrypt-provider` (crypto = wolfCrypt) under an HTTP client, OR a wolfSSL-based
//! client for full-stack wolf/FIPS TLS. The trait exists so tests can inject recorded fixtures.
