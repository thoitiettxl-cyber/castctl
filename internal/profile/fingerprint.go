// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Licensed under the GNU General Public License v3.0 or later.

package profile

import (
	"fmt"
	"slices"
	"strings"
)

// Fingerprint/tls_engine recording (Boss order, PR3) — STORAGE
// ONLY, nothing wired.
//
// FINGERPRINT-HOLD: these settings are RECORDED in PR3 (stored,
// data-validated, displayed). Their EFFECT takes place only after
// the fingerprint-engine evaluation decision (pending). Today all
// traffic uses uTLS chrome regardless of these values. Do NOT wire
// any TLS/ALPN/header behaviour from them here, and do NOT adopt
// "random"/"randomized" presets: they violate the stable-identity
// requirement and are not in the accepted sets below. The accepted
// sets are FIXED STRINGS validated as data in this package; if the
// evaluation later narrows the fingerprint enum, that is a
// post-evaluation change, carried explicitly. No outbound-package
// API is called or depended on (by Boss correction, the
// outbound.ParseFingerprint/SupportedFingerprints calls from the
// earlier fingerprint brief are CANCELLED and must not be
// reintroduced).

// Defaults when a key is absent from the config file: today's
// behaviour. Reads never write defaults back into the user's file;
// see the presence flags on Profile.
const (
	// DefaultFingerprint is the fingerprint preset used when the
	// "fingerprint" key is absent.
	DefaultFingerprint = "chrome"
	// DefaultTLSEngine is the TLS engine used when the "tls_engine"
	// key is absent.
	DefaultTLSEngine = "utls"
)

var (
	validFingerprints = []string{"chrome", "firefox", "ios", "safari"}
	validTLSEngines   = []string{"cronet", "stdlib", "utls"}
)

// SupportedFingerprints returns the accepted "fingerprint" values,
// sorted. Data validation only; see the FINGERPRINT-HOLD comment
// above.
func SupportedFingerprints() []string {
	return slices.Clone(validFingerprints)
}

// SupportedTLSEngines returns the accepted "tls_engine" values,
// sorted. Data validation only; see the FINGERPRINT-HOLD comment
// above.
func SupportedTLSEngines() []string {
	return slices.Clone(validTLSEngines)
}

// validateFingerprintValue rejects anything outside the fixed
// accepted set. Matching is exact: no case folding, no trimming.
// The error names the supported values.
func validateFingerprintValue(v string) error {
	if slices.Contains(validFingerprints, v) {
		return nil
	}
	return fmt.Errorf("fingerprint must be one of %s", strings.Join(validFingerprints, ", "))
}

// validateTLSEngineValue rejects anything outside the fixed
// accepted set. Matching is exact: no case folding, no trimming.
// The error names the supported values.
func validateTLSEngineValue(v string) error {
	if slices.Contains(validTLSEngines, v) {
		return nil
	}
	return fmt.Errorf("tls_engine must be one of %s", strings.Join(validTLSEngines, ", "))
}
