// SPDX-License-Identifier: LGPL-3.0-or-later OR GPL-3.0-or-later
//! himmelblau `IdProvider` adapter over himmelcloak.
//!
//! Implements himmelblau's `IdProvider` trait by driving himmelcloak's
//! `initiate_auth_flow` / `continue_auth_flow` state machine. This is the thin glue that lets
//! himmelblau's PAM/NSS/daemon authenticate against Keycloak through himmelcloak. Keep it small.
