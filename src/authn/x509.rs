/*
 * Himmelcloak native Keycloak authentication
 * SPDX-License-Identifier: LGPL-3.0-or-later OR GPL-3.0-or-later
 */
//! X.509 / PIV / CAC smartcard factor (mTLS). Feature: `x509`.
//! Negotiated at the TLS handshake with a client cert; the cert/key comes from wolfPKCS11.
//! Gov-critical (OMB M-22-09 phishing-resistant MFA).
