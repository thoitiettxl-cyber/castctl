//go:build ignore

// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Licensed under the GNU General Public License v3.0 or later.

// Command compile is the protoc replacement for regenerating
// internal/proto: it compiles .proto files with
// github.com/bufbuild/protocompile (pure Go, the compiler that powers
// buf; no protoc or buf binary is needed on the VM) and invokes the real
// protoc-gen-go binary via the standard plugin protocol
// (CodeGeneratorRequest on stdin, CodeGeneratorResponse on stdout).
//
// This file carries a //go:build ignore tag and lives in its own nested
// module (see go.mod in this directory), so the main module never sees
// the protocompile dependency and `go test ./...` from go/ does not
// build it. Run it only through generate.sh, which builds it in a clean
// copy under /tmp. It writes no product code by itself.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/bufbuild/protocompile"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protodesc"
	"google.golang.org/protobuf/types/descriptorpb"
	"google.golang.org/protobuf/types/pluginpb"
)

func main() {
	protoDir := flag.String("proto-dir", "", "directory containing .proto files (import path root)")
	plugin := flag.String("plugin", "", "path to protoc-gen-go binary")
	outDir := flag.String("out", "", "output root directory for generated files")
	descDir := flag.String("desc-out", "", "directory to write compiled FileDescriptorProto binaries (for comparison)")
	stripPrefix := flag.String("strip-prefix", "", "module prefix to strip from generated file paths (paths=import output)")
	flag.Parse()
	files := flag.Args()
	if *protoDir == "" || *plugin == "" || *outDir == "" || len(files) == 0 {
		fmt.Fprintln(os.Stderr, "usage: compile -proto-dir DIR -plugin PATH -out DIR [-desc-out DIR] [-strip-prefix PREFIX] file.proto...")
		os.Exit(2)
	}
	compiler := protocompile.Compiler{
		Resolver:       &protocompile.SourceResolver{ImportPaths: []string{*protoDir}},
		SourceInfoMode: protocompile.SourceInfoNone,
		MaxParallelism: 1,
	}
	compiled, err := compiler.Compile(context.Background(), files...)
	if err != nil {
		fmt.Fprintf(os.Stderr, "compile: %v\n", err)
		os.Exit(1)
	}
	var protos []*descriptorpb.FileDescriptorProto
	for _, f := range compiled {
		fd := protodesc.ToFileDescriptorProto(f)
		protos = append(protos, fd)
		fmt.Printf("compiled %s package=%s messages=%d enums=%d go_package=%q\n",
			fd.GetName(), fd.GetPackage(), len(fd.GetMessageType()), len(fd.GetEnumType()), fd.GetOptions().GetGoPackage())
		if *descDir != "" {
			b, err := proto.Marshal(fd)
			if err != nil {
				fmt.Fprintf(os.Stderr, "marshal descriptor: %v\n", err)
				os.Exit(1)
			}
			out := filepath.Join(*descDir, filepath.Base(fd.GetName())+".bin")
			if err := os.WriteFile(out, b, 0o644); err != nil {
				fmt.Fprintf(os.Stderr, "write descriptor: %v\n", err)
				os.Exit(1)
			}
			fmt.Printf("wrote descriptor %s (%d bytes)\n", out, len(b))
		}
	}

	req := &pluginpb.CodeGeneratorRequest{
		FileToGenerate: files,
		Parameter:      proto.String("paths=import"),
		ProtoFile:      protos,
	}
	reqBytes, err := proto.Marshal(req)
	if err != nil {
		fmt.Fprintf(os.Stderr, "marshal request: %v\n", err)
		os.Exit(1)
	}
	cmd := exec.Command(*plugin)
	cmd.Stdin = strings.NewReader(string(reqBytes))
	respBytes, err := cmd.Output()
	if err != nil {
		fmt.Fprintf(os.Stderr, "protoc-gen-go: %v\n", err)
		os.Exit(1)
	}
	var resp pluginpb.CodeGeneratorResponse
	if err := proto.Unmarshal(respBytes, &resp); err != nil {
		fmt.Fprintf(os.Stderr, "unmarshal response: %v\n", err)
		os.Exit(1)
	}
	if errStr := resp.GetError(); errStr != "" {
		fmt.Fprintf(os.Stderr, "protoc-gen-go error: %s\n", errStr)
		os.Exit(1)
	}
	for _, f := range resp.GetFile() {
		name := f.GetName()
		fmt.Printf("generated %s (%d bytes)\n", name, len(f.GetContent()))
		// paths=import prefixes the go_package import path; strip the
		// module prefix so files land under the output root.
		rel := strings.TrimPrefix(name, *stripPrefix)
		dest := filepath.Join(*outDir, rel)
		if err := os.MkdirAll(filepath.Dir(dest), 0o755); err != nil {
			fmt.Fprintf(os.Stderr, "mkdir: %v\n", err)
			os.Exit(1)
		}
		if err := os.WriteFile(dest, []byte(f.GetContent()), 0o644); err != nil {
			fmt.Fprintf(os.Stderr, "write: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("wrote %s\n", dest)
	}
}
