// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Licensed under the GNU General Public License v3.0 or later.

// Package fsclient ports fs.py: the Muse "System Files" client.
// Paths are relative to the System Files root and are always POSIX:
// Norm uses the path package, never filepath, exactly as Python
// uses posixpath. All remote operations go through the narrow
// Gateway interface defined here, satisfied by conn.Gateway (the
// real gateway in internal/gateway) and by in-memory fakes in
// tests.
//
// Intentional differences from Python, recorded here so reviewers
// do not "fix" them back:
//
//   - The move operation calls method "fs.rename", not "fs.move":
//     fs.py calls fs.rename and routes.json has no fs.move. The
//     method names are pinned by a LookupRoute test against the
//     embedded routes.json.
//   - edit_in_editor runs the editor directly (exec, no shell),
//     splitting VISUAL/EDITOR shlex-style first. Python runs
//     `editor + " " + shlex.quote(file)` with shell=True. The
//     observable behaviour (editor argv, file edited in place,
//     exit status ignored) is the same; the shell is not.
//   - FS.Get writes files directly, exactly as fs.py's get does.
//     The ".part + rename, skip existing, byte_len warning"
//     behaviour belongs to shared.SaveResources, not to get.
//   - Norm clamps ".." instead of erroring on it: posixpath.normpath
//     on a rooted path can never yield a ".." segment, so fs.py's
//     traversal check is unreachable for rooted input and
//     norm("../etc") is "etc" (pinned by the Python test). The
//     check is ported verbatim anyway, so a future change to the
//     rooting would fail closed.
//   - Put visits local directories in filepath.WalkDir (lexical)
//     order, where Python's os.walk order is filesystem order.
//     The final remote state is identical; only call order differs.
//
// Chunk sizes are package variables (ChunkSize for reads, 4 MiB;
// WriteChunkSize for writes, 1 MiB) mirroring Python's CHUNK and
// WRITE_CHUNK module constants, including the test practice of
// shrinking them. Code that changes them must not run concurrently
// with FS use; tests that shrink them must not use t.Parallel.
package fsclient
