// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Licensed under the GNU General Public License v3.0 or later.

package commands

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path"
	"strings"

	"github.com/thoitiettxl-cyber/muse-cli/go/internal/conn"
	"github.com/thoitiettxl-cyber/muse-cli/go/internal/fsclient"
)

const fsLsHelpText = `usage: muse-cli fs ls [PATH] [-l] [-a] [--json]

List a folder (default: System Files root).

options:
  -l, --long   long listing: type, size, modification time, name.
  -a, --all    include dotfiles.
  --json       print the entries as JSON instead of names.
`

const fsTreeHelpText = `usage: muse-cli fs tree [PATH] [--depth N] [-a] [--json]

Recursive listing.

options:
  --depth N    recursion depth (default 2; a negative depth behaves like 0: one level).
  -a, --all    include dotfiles (any path component starting with ".").
  --json       print [{"path": ..., **entry}] as JSON instead of text.
`

const fsStatHelpText = `usage: muse-cli fs stat PATH

Print file/folder metadata as JSON.
`

const fsCatHelpText = `usage: muse-cli fs cat PATH [--max-bytes N] [--binary]

Print a file to stdout. A NUL byte in the first 8192 bytes without
--binary refuses with exit 1.

options:
  --max-bytes N  read at most N bytes.
  --binary       allow binary output.
`

const fsGetHelpText = `usage: muse-cli fs get PATH [-o DIR] [-r]

Download a file (or a folder with -r) into DIR.

options:
  -o, --output DIR   directory to save into (default .).
  -r, --recursive    download folders recursively.
`

const fsFindHelpText = `usage: muse-cli fs find NAME [--limit N]

Search by name substring. Prints the matching entries as JSON.

options:
  --limit N    maximum results.
`

const fsPutHelpText = `usage: muse-cli fs put LOCAL REMOTE [-r] [-n]

Upload a local file (or folder with -r) to a remote path.

options:
  -r, --recursive    upload folders recursively.
  -n, --no-clobber   refuse to overwrite an existing remote file.
`

const fsWriteHelpText = `usage: muse-cli fs write REMOTE [--append] [-n]

Write stdin to a remote file. --append reads the old content first
and overwrites with old+new (one full write; chunking is owned by
the fs client).

options:
  --append         append to the existing content.
  -n, --no-clobber  refuse to overwrite an existing remote file.
`

const fsEditHelpText = `usage: muse-cli fs edit REMOTE [--replace OLD NEW]...

Edit a remote file: apply --replace pairs in order (repeatable), or
open $VISUAL/$EDITOR (default vi) when no --replace is given. An
unchanged file prints {"path": ..., "changed": false} and writes
nothing.

options:
  --replace OLD NEW  replace every occurrence of OLD with NEW.
`

const fsMkdirHelpText = `usage: muse-cli fs mkdir PATH

Create a folder, with parents. Prints the result as JSON.
`

const fsMvHelpText = `usage: muse-cli fs mv SRC DST [-f]

Move/rename a remote path.

options:
  -f, --force    overwrite the destination.
`

const fsRmHelpText = `usage: muse-cli fs rm PATH [-r] [--yes]

Delete a remote path. Refuses without --yes, before connecting.

options:
  -r, --recursive  delete folders recursively.
  --yes            confirm the deletion.
`

var fsSubcommands = []string{"ls", "tree", "stat", "cat", "get", "find", "put", "write", "edit", "mkdir", "mv", "rm"}

func init() {
	registerCommand(&commandSpec{
		name:     "fs",
		help:     "browse/read/write Muse's System Files (agent home)",
		helpText: fsHelpText,
		handler:  cmdFS,
	})
	registerFlags("fs", "fs <subcommand> [options]", nil)
}

// cmdFS dispatches fs subcommands. The fs parser is separate from
// the top-level parser: each subcommand has its own flags, and
// --help after the subcommand prints that subcommand's help.
func cmdFS(ctx context.Context, env *Env, g *globalOpts, args []string) error {
	if len(args) == 0 {
		fmt.Fprintln(env.stderr(), "muse-cli: the following arguments are required: subcommand")
		fmt.Fprint(env.stderr(), fsHelpText)
		return errCode(2, nil)
	}
	if args[0] == "--help" || args[0] == "-h" {
		fmt.Fprint(env.stdout(), fsHelpText)
		return errHelpShown
	}
	sub := args[0]
	rest := args[1:]
	switch sub {
	case "ls":
		return fsLs(ctx, env, g, rest)
	case "tree":
		return fsTree(ctx, env, g, rest)
	case "stat":
		return fsStat(ctx, env, g, rest)
	case "cat":
		return fsCat(ctx, env, g, rest)
	case "get":
		return fsGet(ctx, env, g, rest)
	case "find":
		return fsFind(ctx, env, g, rest)
	case "put":
		return fsPut(ctx, env, g, rest)
	case "write":
		return fsWrite(ctx, env, g, rest)
	case "edit":
		return fsEdit(ctx, env, g, rest)
	case "mkdir":
		return fsMkdir(ctx, env, g, rest)
	case "mv":
		return fsMv(ctx, env, g, rest)
	case "rm":
		return fsRm(ctx, env, g, rest)
	default:
		fmt.Fprintf(env.stderr(), "muse-cli: argument subcommand: invalid choice: %q (choose from %s)\n", sub, strings.Join(fsSubcommands, ", "))
		return errCode(2, nil)
	}
}

// runFS builds the runtime and runs fn with an FS over the leased
// gateway. Traversal (Norm) errors from the fs client are
// validation failures (exit 2, like Python's ValueError); callers
// pre-validate paths with fsclient.Norm so the mapping is exact.
func runFS(ctx context.Context, env *Env, g *globalOpts, fn func(*fsclient.FS) error) error {
	return runNetwork(ctx, env, g, func(rt *Runtime) error {
		return rt.Muse.WithGateway(ctx, func(gw conn.Gateway) error {
			return fn(fsclient.New(gw))
		})
	})
}

func fsParse(sub string, args []string, env *Env) (*parsed, error) {
	defs, helpText := fsDefs(sub)
	ap := &argParser{defs: defs, helpText: helpText, prog: "muse-cli fs " + sub}
	p, helpShown, err := ap.parse(args, env.stdout())
	if err != nil {
		if pe, ok := err.(*parserError); ok {
			fmt.Fprintf(env.stderr(), "muse-cli: %s\n", pe.msg)
			fmt.Fprintf(env.stderr(), "usage: muse-cli fs %s\n", sub)
			return nil, errCode(2, pe)
		}
		return nil, err
	}
	if helpShown {
		return nil, errHelpShown
	}
	return p, nil
}

func fsDefs(sub string) ([]flagDef, string) {
	switch sub {
	case "ls":
		return []flagDef{
			{name: "long", short: 'l', kind: flagBool},
			{name: "all", short: 'a', kind: flagBool},
			{name: "json", kind: flagBool},
		}, fsLsHelpText
	case "tree":
		return []flagDef{
			intFlag("depth", 0, 2),
			{name: "all", short: 'a', kind: flagBool},
			{name: "json", kind: flagBool},
		}, fsTreeHelpText
	case "stat":
		return nil, fsStatHelpText
	case "cat":
		return []flagDef{
			{name: "max-bytes", kind: flagInt},
			{name: "binary", kind: flagBool},
		}, fsCatHelpText
	case "get":
		return []flagDef{
			{name: "output", short: 'o', kind: flagString},
			{name: "recursive", short: 'r', kind: flagBool},
		}, fsGetHelpText
	case "find":
		return []flagDef{
			{name: "limit", kind: flagInt},
		}, fsFindHelpText
	case "put":
		return []flagDef{
			{name: "recursive", short: 'r', kind: flagBool},
			{name: "no-clobber", short: 'n', kind: flagBool},
		}, fsPutHelpText
	case "write":
		return []flagDef{
			{name: "append", kind: flagBool},
			{name: "no-clobber", short: 'n', kind: flagBool},
		}, fsWriteHelpText
	case "edit":
		return []flagDef{
			{name: "replace", kind: flagPairList},
		}, fsEditHelpText
	case "mkdir":
		return nil, fsMkdirHelpText
	case "mv":
		return []flagDef{
			{name: "force", short: 'f', kind: flagBool},
		}, fsMvHelpText
	case "rm":
		return []flagDef{
			{name: "recursive", short: 'r', kind: flagBool},
			{name: "yes", kind: flagBool},
		}, fsRmHelpText
	}
	return nil, ""
}

func fsPositionals(p *parsed, names []string) error {
	return checkPositionals(p, names, "fs")
}

// normOr2 validates a remote path the way fsclient.Norm does, mapped
// to exit 2.
func normOr2(p string) error {
	_, err := fsclient.Norm(p)
	if err != nil {
		return errCode(2, err)
	}
	return nil
}

func fsLs(ctx context.Context, env *Env, g *globalOpts, args []string) error {
	p, err := fsParse("ls", args, env)
	if err != nil {
		return err
	}
	if len(p.positionals) > 1 {
		return usageErr(&parserError{msg: fmt.Sprintf("unrecognized arguments: %s", strings.Join(p.positionals[1:], " "))})
	}
	remotePath := ""
	if len(p.positionals) == 1 {
		remotePath = p.positionals[0]
	}
	if err := normOr2(remotePath); err != nil {
		return err
	}
	return runFS(ctx, env, g, func(f *fsclient.FS) error {
		ents, err := f.ListDir(ctx, remotePath)
		if err != nil {
			return err
		}
		if !p.bool("all") {
			filtered := ents[:0]
			for _, e := range ents {
				if !strings.HasPrefix(e.Name, ".") {
					filtered = append(filtered, e)
				}
			}
			ents = filtered
		}
		if p.bool("json") {
			if ents == nil {
				ents = []fsclient.Entry{}
			}
			return writeJSON(env.stdout(), ents)
		}
		for _, e := range ents {
			name := e.Name
			if e.Type == "directory" {
				name += "/"
			}
			if p.bool("long") {
				typeChar := '?'
				if e.Type != "" {
					typeChar = []rune(e.Type)[0]
				}
				fmt.Fprintf(env.stdout(), "%c %7s %-19s %s\n", typeChar, fsclient.FmtSize(e.Size), pad19(e.ModifiedAt), name)
			} else {
				fmt.Fprintln(env.stdout(), name)
			}
		}
		return nil
	})
}

func pad19(s string) string {
	r := []rune(s)
	if len(r) > 19 {
		r = r[:19]
	}
	for len(r) < 19 {
		r = append(r, ' ')
	}
	return string(r)
}

func fsTree(ctx context.Context, env *Env, g *globalOpts, args []string) error {
	p, err := fsParse("tree", args, env)
	if err != nil {
		return err
	}
	if len(p.positionals) > 1 {
		return usageErr(&parserError{msg: fmt.Sprintf("unrecognized arguments: %s", strings.Join(p.positionals[1:], " "))})
	}
	remotePath := ""
	if len(p.positionals) == 1 {
		remotePath = p.positionals[0]
	}
	if err := normOr2(remotePath); err != nil {
		return err
	}
	return runFS(ctx, env, g, func(f *fsclient.FS) error {
		depth := int(p.intVal("depth"))
		if depth < 0 {
			// Python's walk guard (_level+1 < depth) is
			// false at level 0 for every negative depth:
			// --depth -1 lists ONE level, exactly like 0.
			// A negative depth must never reach Walk, whose
			// negative depths are the internal unlimited
			// sentinel used by `fs get`.
			depth = 0
		}
		rows, err := f.Walk(ctx, remotePath, depth)
		if err != nil {
			return err
		}
		filtered := rows[:0]
		for _, r := range rows {
			if p.bool("all") {
				filtered = append(filtered, r)
				continue
			}
			dotted := false
			for _, comp := range strings.Split(r.Rel, "/") {
				if strings.HasPrefix(comp, ".") {
					dotted = true
					break
				}
			}
			if !dotted {
				filtered = append(filtered, r)
			}
		}
		rows = filtered
		if p.bool("json") {
			return writeTreeJSON(env.stdout(), rows)
		}
		header := remotePath
		if header == "" {
			header = "/"
		}
		fmt.Fprintln(env.stdout(), header)
		for _, r := range rows {
			name := r.Entry.Name
			if r.Entry.Type == "directory" {
				name += "/"
			}
			fmt.Fprintf(env.stdout(), "%s%s\n", strings.Repeat("  ", r.Level+1), name)
		}
		return nil
	})
}

// writeTreeJSON writes [{"path": rel, **entry}] with path first,
// matching Python's {"path": r, **e} dict order.
func writeTreeJSON(w io.Writer, rows []fsclient.WalkEntry) error {
	var b strings.Builder
	b.WriteString("[\n")
	for i, r := range rows {
		entryJSON, err := json.Marshal(r.Entry)
		if err != nil {
			return err
		}
		pathJSON, err := json.Marshal(r.Rel)
		if err != nil {
			return err
		}
		if i > 0 {
			b.WriteString(",\n")
		}
		b.WriteString("  {\"path\":")
		b.Write(pathJSON)
		// Splice the entry object after its opening brace.
		if len(entryJSON) > 1 {
			b.WriteString(",")
			b.Write(entryJSON[1:])
		} else {
			b.WriteString("}")
		}
	}
	if len(rows) > 0 {
		b.WriteString("\n")
	}
	b.WriteString("]\n")
	_, err := io.WriteString(w, b.String())
	return err
}

func fsStat(ctx context.Context, env *Env, g *globalOpts, args []string) error {
	p, err := fsParse("stat", args, env)
	if err != nil {
		return err
	}
	if err := fsPositionals(p, []string{"path"}); err != nil {
		return usageErr(err)
	}
	remotePath := p.positionals[0]
	if err := normOr2(remotePath); err != nil {
		return err
	}
	return runFS(ctx, env, g, func(f *fsclient.FS) error {
		st, err := f.Stat(ctx, remotePath)
		if err != nil {
			return err
		}
		return writeJSON(env.stdout(), st)
	})
}

func fsCat(ctx context.Context, env *Env, g *globalOpts, args []string) error {
	p, err := fsParse("cat", args, env)
	if err != nil {
		return err
	}
	if err := fsPositionals(p, []string{"path"}); err != nil {
		return usageErr(err)
	}
	remotePath := p.positionals[0]
	if err := normOr2(remotePath); err != nil {
		return err
	}
	var maxBytes *int64
	if p.intIsSet("max-bytes") {
		v := p.intVal("max-bytes")
		maxBytes = &v
	}
	return runFS(ctx, env, g, func(f *fsclient.FS) error {
		data, err := f.ReadFile(ctx, remotePath, maxBytes)
		if err != nil {
			return err
		}
		head := data
		if len(head) > 8192 {
			head = head[:8192]
		}
		if bytes.Contains(head, []byte{0}) && !p.bool("binary") {
			return errCodef(1, "%s: binary file (%d bytes); use `fs get` or --binary", remotePath, len(data))
		}
		_, err = env.stdout().Write(data)
		return err
	})
}

func fsGet(ctx context.Context, env *Env, g *globalOpts, args []string) error {
	p, err := fsParse("get", args, env)
	if err != nil {
		return err
	}
	if err := fsPositionals(p, []string{"path"}); err != nil {
		return usageErr(err)
	}
	remotePath := p.positionals[0]
	if err := normOr2(remotePath); err != nil {
		return err
	}
	output := "."
	if p.strIsSet("output") {
		output = p.str("output")
	}
	return runFS(ctx, env, g, func(f *fsclient.FS) error {
		if err := os.MkdirAll(output, 0o777); err != nil {
			return err
		}
		saved, err := f.Get(ctx, remotePath, output, p.bool("recursive"))
		if err != nil {
			return err
		}
		if saved == nil {
			saved = []string{}
		}
		return writeJSON(env.stdout(), map[string]any{"saved": saved})
	})
}

func fsFind(ctx context.Context, env *Env, g *globalOpts, args []string) error {
	p, err := fsParse("find", args, env)
	if err != nil {
		return err
	}
	if err := fsPositionals(p, []string{"name"}); err != nil {
		return usageErr(err)
	}
	return runFS(ctx, env, g, func(f *fsclient.FS) error {
		ents, err := f.Search(ctx, p.positionals[0], p.intVal("limit"))
		if err != nil {
			return err
		}
		if ents == nil {
			ents = []fsclient.Entry{}
		}
		return writeJSON(env.stdout(), ents)
	})
}

func fsPut(ctx context.Context, env *Env, g *globalOpts, args []string) error {
	p, err := fsParse("put", args, env)
	if err != nil {
		return err
	}
	if err := fsPositionals(p, []string{"local", "remote"}); err != nil {
		return usageErr(err)
	}
	local, remote := p.positionals[0], p.positionals[1]
	if err := normOr2(remote); err != nil {
		return err
	}
	return runFS(ctx, env, g, func(f *fsclient.FS) error {
		results, err := f.Put(ctx, local, remote, p.bool("recursive"), !p.bool("no-clobber"))
		if err != nil {
			return err
		}
		if results == nil {
			results = []fsclient.WriteResult{}
		}
		return writeJSON(env.stdout(), results)
	})
}

func fsWrite(ctx context.Context, env *Env, g *globalOpts, args []string) error {
	p, err := fsParse("write", args, env)
	if err != nil {
		return err
	}
	if err := fsPositionals(p, []string{"remote"}); err != nil {
		return usageErr(err)
	}
	remote := p.positionals[0]
	if err := normOr2(remote); err != nil {
		return err
	}
	// Python reads stdin before connecting.
	data, err := io.ReadAll(env.stdin())
	if err != nil {
		return err
	}
	return runFS(ctx, env, g, func(f *fsclient.FS) error {
		if p.bool("append") {
			old, err := f.ReadFile(ctx, remote, nil)
			if err != nil {
				return err
			}
			combined := append(old, data...)
			r, err := f.WriteFile(ctx, remote, combined, true, true)
			if err != nil {
				return err
			}
			return writeJSON(env.stdout(), r)
		}
		r, err := f.WriteFile(ctx, remote, data, !p.bool("no-clobber"), true)
		if err != nil {
			return err
		}
		return writeJSON(env.stdout(), r)
	})
}

func fsEdit(ctx context.Context, env *Env, g *globalOpts, args []string) error {
	p, err := fsParse("edit", args, env)
	if err != nil {
		return err
	}
	if err := fsPositionals(p, []string{"remote"}); err != nil {
		return usageErr(err)
	}
	remote := p.positionals[0]
	if err := normOr2(remote); err != nil {
		return err
	}
	return runFS(ctx, env, g, func(f *fsclient.FS) error {
		before, err := f.ReadFile(ctx, remote, nil)
		if err != nil {
			return err
		}
		var after []byte
		if pairs := p.pairs["replace"]; len(pairs) > 0 {
			text := string(before)
			for _, pr := range pairs {
				text, err = fsclient.ApplyReplace(text, pr[0], pr[1], -1)
				if err != nil {
					// A failed replacement is a ValueError in
					// Python: exit 2.
					return errCode(2, err)
				}
			}
			after = []byte(text)
		} else {
			after, err = fsclient.EditInEditor(ctx, before, path.Ext(remote))
			if err != nil {
				return err
			}
		}
		if bytes.Equal(after, before) {
			return writeJSON(env.stdout(), map[string]any{"path": remote, "changed": false})
		}
		r, err := f.WriteFile(ctx, remote, after, true, true)
		if err != nil {
			return err
		}
		return writeEditResult(env.stdout(), r, true)
	})
}

// writeEditResult writes {**write_result, "changed": true} with the
// write result's fields first, matching Python's {**r, "changed": True}.
func writeEditResult(w io.Writer, r fsclient.WriteResult, changed bool) error {
	var b strings.Builder
	b.WriteString("{\n")
	pathJSON, _ := json.Marshal(r.Path)
	b.WriteString("  \"path\": ")
	b.Write(pathJSON)
	fmt.Fprintf(&b, ",\n  \"bytes_written\": %d", r.BytesWritten)
	fmt.Fprintf(&b, ",\n  \"changed\": %v", changed)
	b.WriteString("\n}\n")
	_, err := io.WriteString(w, b.String())
	return err
}

func fsMkdir(ctx context.Context, env *Env, g *globalOpts, args []string) error {
	p, err := fsParse("mkdir", args, env)
	if err != nil {
		return err
	}
	if err := fsPositionals(p, []string{"path"}); err != nil {
		return usageErr(err)
	}
	remotePath := p.positionals[0]
	if err := normOr2(remotePath); err != nil {
		return err
	}
	return runFS(ctx, env, g, func(f *fsclient.FS) error {
		r, err := f.Mkdir(ctx, remotePath, true)
		if err != nil {
			return err
		}
		return writeJSON(env.stdout(), r)
	})
}

func fsMv(ctx context.Context, env *Env, g *globalOpts, args []string) error {
	p, err := fsParse("mv", args, env)
	if err != nil {
		return err
	}
	if err := fsPositionals(p, []string{"src", "dst"}); err != nil {
		return usageErr(err)
	}
	src, dst := p.positionals[0], p.positionals[1]
	if err := normOr2(src); err != nil {
		return err
	}
	if err := normOr2(dst); err != nil {
		return err
	}
	return runFS(ctx, env, g, func(f *fsclient.FS) error {
		r, err := f.Move(ctx, src, dst, p.bool("force"), true)
		if err != nil {
			return err
		}
		return writeJSON(env.stdout(), r)
	})
}

func fsRm(ctx context.Context, env *Env, g *globalOpts, args []string) error {
	p, err := fsParse("rm", args, env)
	if err != nil {
		return err
	}
	if err := fsPositionals(p, []string{"path"}); err != nil {
		return usageErr(err)
	}
	// Refused before connecting, exactly like Python.
	if !p.bool("yes") {
		return errCodef(2, "refusing to delete without --yes")
	}
	remotePath := p.positionals[0]
	if err := normOr2(remotePath); err != nil {
		return err
	}
	return runFS(ctx, env, g, func(f *fsclient.FS) error {
		r, err := f.Delete(ctx, remotePath, p.bool("recursive"))
		if err != nil {
			return err
		}
		return writeJSON(env.stdout(), r)
	})
}
