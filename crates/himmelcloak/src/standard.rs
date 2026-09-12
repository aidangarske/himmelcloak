// SPDX-License-Identifier: LGPL-3.0-or-later OR GPL-3.0-or-later
//! Standard tier: the direct-grant token endpoint fast path for password / TOTP / X.509.
//!
//! OPTIONAL optimization only, many gov realms disable ROPC/direct-grant, in which case those
//! factors route through the flow-driver instead. The flow-driver is the universal engine.
