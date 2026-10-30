// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Licensed under the GNU General Public License v3.0 or later.

package deliver

// ExportGuidance is the manual guidance AuthExport returns. It
// tells the user how to establish a login by hand, portably: no
// platform tool is named, because no automatic extraction exists
// in this build.
const ExportGuidance = `cookie export is not available in this build: no automatic cookie extraction is implemented yet.

Log in at https://muse.ai/ in your browser, leave the tab open, and run "muse-cli auth export" again after a cookie source exists.

Copy the login by hand instead:
  1. In your browser, open https://muse.ai/ and log in.
  2. Open the browser developer tools and read the cookies for https://muse.ai/.
  3. Write one line to the active profile's cookies.txt file:
       hatch_sess=VALUE; other_name=other_value
     hatch_sess is required. Separate cookies with "; ".
  4. Set the file mode to 600.
  5. Run "muse-cli status" to check the login.

No file was written or changed.`

// ExportError is the typed error AuthExport always returns. It
// carries the manual guidance in Guidance so the commands layer
// can print it to stderr and exit 1, matching Python's exit code
// for the missing-extraction-tool path (cli.py:498-500).
// Errors.Is/As callers can match *ExportError; ExitCode reports 1.
type ExportError struct {
	Guidance string
}

func (e *ExportError) Error() string {
	if e == nil {
		return "deliver: cookie export unavailable"
	}
	return e.Guidance
}

// ExitCode reports the process exit code for this error: 1,
// Python's exact exit code for the missing-tool path.
func (e *ExportError) ExitCode() int { return 1 }

// AuthExport is guidance-only, by coordinator decision. It never
// invokes any browser subprocess, never reads any browser cookie
// store, and never writes any file — there is no write path in
// this function at all, so the never-clobber invariant (never
// replace a working login with an empty or logged-out cookie set,
// cli.py:505-512) holds structurally: the existing cookies file
// is always left unchanged.
//
// Real cookie extraction is CARRIED, awaiting the login-research
// decision (native/relay/import); the login hold forbids any new
// login flow until that decision is approved. This is a
// deliberate portable subset, not parity with Python's
// browser-driven export.
//
// It always returns an *ExportError carrying ExportGuidance.
// Callers print the guidance to stderr and exit 1.
func AuthExport() error {
	return &ExportError{Guidance: ExportGuidance}
}
