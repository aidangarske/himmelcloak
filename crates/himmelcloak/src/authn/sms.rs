/*
 * Himmelcloak native Keycloak authentication
 * SPDX-License-Identifier: LGPL-3.0-or-later OR GPL-3.0-or-later
 */
//! SMS OTP factor. Feature: `sms`.
//! NOTE: SMS is NOT in core Keycloak, it is always a third-party/custom authenticator SPI, so
//! this drives whatever SMS authenticator the customer installed (form fields vary). Support the
//! common ones + a configurable form mapping. `Challenge::Sms` / `Answer::Sms`.
