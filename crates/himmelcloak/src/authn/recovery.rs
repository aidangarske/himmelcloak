// SPDX-License-Identifier: LGPL-3.0-or-later OR GPL-3.0-or-later
//! Recovery codes factor. Feature: `recovery`.
//! Keycloak `recovery-authn-codes` authenticator: the page names the code index; POST the code in
//! `recoveryCodeInput`. No crypto, a plain form step. `Challenge::RecoveryCode` / `Answer::RecoveryCode`.
