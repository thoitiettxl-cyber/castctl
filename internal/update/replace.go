// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Licensed under the GNU General Public License v3.0 or later.

package update

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
)

// Lock file name in the target directory. The file is never deleted
// (the castctl config-guard pattern): deleting it would race a
// concurrent opener. Closing the file releases the flock, including
// on SIGKILL.
const lockFileName = ".castctl-update.lock"

// Hooks overridable by in-package tests for failure injection.
// Production values are the real syscalls.
var (
	renameFunc  = os.Rename
	syncDirFunc = syncDir
	execCheckFn = runExecCheck
)

// dirSyncError reports a directory-sync failure AFTER a successful
// rename: the new binary IS in place, but crash-durability of the
// rename is unproven (H-83). Callers must surface it distinctly
// from a pre-rename failure, where the old binary is intact.
type dirSyncError struct{ err error }

func (e *dirSyncError) Error() string {
	return "update: directory sync failed after replace; the new binary is in place but its durability is not guaranteed"
}
func (e *dirSyncError) Unwrap() error { return e.err }

// install performs the live pipeline under the directory lock:
// checksums fetch, asset download to a temp file, hash verification,
// extraction, ELF validation, exec check, re-hash, and atomic
// replace. Every error before the rename leaves the old binary
// intact and removes temp files; a directory-sync failure after a
// successful rename returns an error with the new binary in place
// (see dirSyncError).
func (u *updater) install(ctx context.Context, res Result, sel *selection, target string, targetMode os.FileMode) (Result, error) {
	dir := filepath.Dir(target)
	unlock, held, err := acquireUpdateLock(dir)
	if err != nil {
		return Result{}, wrapError(1, "update: cannot lock the update directory", err)
	}
	if held {
		return Result{}, newError(1, "update: another update is already in progress")
	}
	defer unlock()

	sums, err := u.fetchChecksums(ctx, sel)
	if err != nil {
		return Result{}, err
	}
	wantDigest, ok := sums[sel.assetName]
	if !ok {
		return Result{}, newError(1, "update: the checksums file has no entry for the release asset")
	}

	// Download to a temp file in the SAME directory as the target
	// (same filesystem, so the rename cannot hit EXDEV), 0600,
	// O_EXCL random suffix. Removed on every path below.
	assetTmp, err := os.CreateTemp(dir, ".castctl-update-*")
	if err != nil {
		return Result{}, wrapError(1, "update: cannot create a temporary file in the binary directory", err)
	}
	assetTmpPath := assetTmp.Name()
	defer os.Remove(assetTmpPath)
	digest, err := u.downloadAsset(ctx, sel.assetURL, sel.assetSize, assetTmp)
	_ = assetTmp.Close()
	if err != nil {
		return Result{}, err
	}
	if !bytes.Equal(digest, wantDigest) {
		return Result{}, newError(1, "update: the downloaded asset does not match the checksums file")
	}

	// Extract to a second temp file in the same directory.
	extractedTmp, err := os.CreateTemp(dir, ".castctl-update-*")
	if err != nil {
		return Result{}, wrapError(1, "update: cannot create a temporary file in the binary directory", err)
	}
	extractedTmpPath := extractedTmp.Name()
	defer os.Remove(extractedTmpPath)
	assetFile, err := os.Open(assetTmpPath)
	if err != nil {
		_ = extractedTmp.Close()
		return Result{}, wrapError(1, "update: cannot re-read the downloaded asset", err)
	}
	extractedHash, err := extractCastctl(assetFile, extractedTmp)
	_ = assetFile.Close()
	if err != nil {
		_ = extractedTmp.Close()
		return Result{}, err
	}
	if err := extractedTmp.Sync(); err != nil {
		_ = extractedTmp.Close()
		return Result{}, wrapError(1, "update: cannot sync the extracted binary", err)
	}
	if err := extractedTmp.Close(); err != nil {
		return Result{}, wrapError(1, "update: cannot close the extracted binary", err)
	}
	_ = os.Remove(assetTmpPath) // asset temp no longer needed

	// Preserve the target's Perm() (0777 rwx) bits now, BEFORE the
	// exec check (which needs +x) and the rename: the temp file is
	// created 0600, the installed mode must never come from the
	// archive header, and setuid/setgid/sticky bits of the old
	// binary are dropped (Perm() carries rwx bits only).
	if err := os.Chmod(extractedTmpPath, targetMode); err != nil {
		return Result{}, wrapError(1, "update: cannot set permissions on the new binary", err)
	}

	// ELF/arch validation on the extracted file, no execution.
	elfFile, err := os.Open(extractedTmpPath)
	if err != nil {
		return Result{}, wrapError(1, "update: cannot re-read the extracted binary", err)
	}
	err = validateELF(elfFile, runtime.GOARCH)
	_ = elfFile.Close()
	if err != nil {
		return Result{}, err
	}

	// Exec check AFTER checksum verification only, on the
	// checksum-verified bytes (decision 7b). Residual risk is
	// documented: checksums prove match-to-published-bytes only.
	if err := execCheckFn(ctx, extractedTmpPath, sel.target); err != nil {
		return Result{}, err
	}

	// Re-hash immediately before rename: the exec'd bytes must be
	// the bytes that get installed (V-06).
	rehash, err := hashFile(extractedTmpPath)
	if err != nil {
		return Result{}, wrapError(1, "update: cannot re-read the extracted binary", err)
	}
	if !bytes.Equal(rehash, extractedHash) {
		return Result{}, newError(1, "update: the extracted binary changed between verification and replace; refusing to install it")
	}

	// Fsync the temp file (mode already set above), rename once,
	// fsync the directory.
	syncFile, err := os.OpenFile(extractedTmpPath, os.O_RDWR, 0)
	if err != nil {
		return Result{}, wrapError(1, "update: cannot re-open the new binary", err)
	}
	syncErr := syncFile.Sync()
	_ = syncFile.Close()
	if syncErr != nil {
		return Result{}, wrapError(1, "update: cannot sync the new binary", syncErr)
	}
	if err := renameFunc(extractedTmpPath, target); err != nil {
		return Result{}, wrapError(1, "update: cannot replace the running binary", err)
	}
	// The rename succeeded: the deferred Remove is now a no-op.
	if err := syncDirFunc(dir); err != nil {
		if isDirSyncTolerable(err) {
			// Filesystems that do not support directory fsync
			// (ENOTSUP/EINVAL) still hold the rename; the error
			// is tolerated and the run succeeds silently (H-92).
		} else {
			res.Replaced = true
			res.Target = sel.target
			res.AssetName = sel.assetName
			return res, &Error{code: 1, msg: (&dirSyncError{}).Error(), cause: err}
		}
	}
	res.Replaced = true
	res.Target = sel.target
	res.AssetName = sel.assetName
	u.printf("castctl updated: %s -> %s (%s)", res.Current.String(), sel.target.String(), sel.assetName)
	return res, nil
}

// dryRun verifies everything a live run would verify except the
// exec check (which needs a file on disk), the chmod, the re-hash,
// the lock, and the replace itself, with ZERO writes: no lock file,
// no temp files, no directory changes. The asset and the extracted
// binary live in memory, bounded by the same caps as the live path.
func (u *updater) dryRun(ctx context.Context, res Result, sel *selection, target string, targetMode os.FileMode) (Result, error) {
	sums, err := u.fetchChecksums(ctx, sel)
	if err != nil {
		return Result{}, err
	}
	wantDigest, ok := sums[sel.assetName]
	if !ok {
		return Result{}, newError(1, "update: the checksums file has no entry for the release asset")
	}
	var assetBuf bytes.Buffer
	digest, err := u.downloadAsset(ctx, sel.assetURL, sel.assetSize, &assetBuf)
	if err != nil {
		return Result{}, err
	}
	if !bytes.Equal(digest, wantDigest) {
		return Result{}, newError(1, "update: the downloaded asset does not match the checksums file")
	}
	var extractedBuf bytes.Buffer
	if _, err := extractCastctl(bytes.NewReader(assetBuf.Bytes()), &extractedBuf); err != nil {
		return Result{}, err
	}
	if err := validateELFBytes(extractedBuf.Bytes(), runtime.GOARCH); err != nil {
		return Result{}, err
	}
	res.Target = sel.target
	res.AssetName = sel.assetName
	u.printf("dry-run: would update %s -> %s", res.Current.String(), sel.target.String())
	u.printf("dry-run: asset %s (%s)", sel.assetName, sel.assetURL)
	u.printf("dry-run: checksums verified (sha256 against checksums.txt)")
	u.printf("dry-run: would replace %s (permissions %04o preserved)", target, targetMode)
	u.printf("dry-run: exec check skipped in dry-run; it runs before replace in a real update")
	return res, nil
}

// fetchChecksums downloads and parses checksums.txt. The file is
// small and capped; it is held in memory and never written to disk.
func (u *updater) fetchChecksums(ctx context.Context, sel *selection) (map[string][]byte, error) {
	body, herr := u.fetchBytes(ctx, sel.checksumsURL, maxChecksumsBytes, metadataTimeout)
	if herr != nil {
		if herr.status == http.StatusNotFound {
			return nil, wrapError(1, "update: the release has no checksums file", herr)
		}
		return nil, wrapError(1, "update: failed to fetch the checksums file", herr)
	}
	sums, err := ParseChecksums(body)
	if err != nil {
		return nil, wrapError(1, "update: the checksums file is malformed", err)
	}
	return sums, nil
}

func hashFile(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return nil, err
	}
	return h.Sum(nil), nil
}

// syncDir fsyncs a directory so a just-completed rename is durable
// across a crash (H-86). There is no stdlib helper: open the
// directory and Sync it.
func syncDir(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}

// isDirSyncTolerable reports whether a directory-sync error may be
// tolerated, succeeding silently: filesystems that return
// ENOTSUP/EINVAL for directory fsync still hold the rename.
func isDirSyncTolerable(err error) bool {
	return errors.Is(err, syscall.EINVAL) || errors.Is(err, syscall.ENOTSUP) || errors.Is(err, syscall.EOPNOTSUPP)
}

// runExecCheck executes the extracted binary, unsandboxed, with
// argv --version in a clean minimal environment (empty env: no
// LD_PRELOAD or other injection variables are inherited), closed
// stdin, a 10s timeout, and capped stdout. The output must be
// exactly one line, "castctl <version>", parsed and compared equal
// to the target version; an optional parenthetical after the
// version is shape-only (its content is not parsed). Any failure,
// timeout, or mismatch refuses the update with the old binary
// intact. A child process detached by the candidate binary would
// survive the timeout kill; that residual is recorded in the docs.
//
// This executes bytes that already passed checksum verification
// against the release. It proves the binary runs on this machine
// and reports the claimed version; it does NOT prove provenance
// (see the no-signature limitation in the docs).
func runExecCheck(ctx context.Context, path string, want Version) error {
	ctx, cancel := context.WithTimeout(ctx, execCheckTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, path, "--version")
	cmd.Env = []string{}
	cmd.Dir = filepath.Dir(path)
	cmd.Stdin = nil // /dev/null
	cmd.Stderr = io.Discard
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return newError(1, "update: cannot check the downloaded binary")
	}
	if err := cmd.Start(); err != nil {
		return newError(1, "update: cannot execute the downloaded binary")
	}
	out, readErr := io.ReadAll(io.LimitReader(stdout, maxExecOutputBytes+1))
	if len(out) > maxExecOutputBytes {
		cancel() // kill a flooding child promptly instead of waiting out the timeout
	}
	waitErr := cmd.Wait()
	if ctx.Err() == context.DeadlineExceeded {
		return newError(1, "update: the downloaded binary did not answer --version in time")
	}
	if readErr != nil {
		return newError(1, "update: cannot read the downloaded binary --version output")
	}
	if len(out) > maxExecOutputBytes {
		return newError(1, "update: the downloaded binary --version output is too large")
	}
	if waitErr != nil {
		return newError(1, "update: the downloaded binary --version check failed")
	}
	if err := checkVersionOutput(out, want); err != nil {
		return err
	}
	return nil
}

// checkVersionOutput requires exactly one line, "castctl <version>"
// optionally followed by " (<commit> <date>)", where <version>
// parses and compares equal to the target version. The
// parenthetical is shape-only: only its surrounding parentheses
// are checked, its content is never parsed. Anything else — extra
// lines, injected lines, trailing garbage, control bytes — refuses.
func checkVersionOutput(out []byte, want Version) error {
	fail := func() error {
		return newError(1, "update: the downloaded binary does not report the target version")
	}
	for _, b := range out {
		if (b < 0x20 && b != '\n') || b == 0x7f {
			return fail()
		}
	}
	s := strings.TrimSuffix(string(out), "\n")
	if strings.Contains(s, "\n") || len(s) == 0 || len(s) > 256 {
		return fail()
	}
	if !strings.HasPrefix(s, "castctl ") {
		return fail()
	}
	rest := strings.TrimPrefix(s, "castctl ")
	verStr := rest
	if i := strings.IndexByte(rest, ' '); i >= 0 {
		verStr = rest[:i]
		tail := rest[i:]
		if !strings.HasPrefix(tail, " (") || !strings.HasSuffix(tail, ")") {
			return fail()
		}
	}
	got, err := ParseVersion(verStr)
	if err != nil {
		return fail()
	}
	if CompareVersions(got, want) != 0 {
		return fail()
	}
	return nil
}
