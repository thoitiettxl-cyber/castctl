// Command fakehang sleeps forever on --version. Test-only fixture.
package main

import (
	"fmt"
	"os"
	"time"
)

func main() {
	if len(os.Args) > 1 && os.Args[1] == "--version" {
		time.Sleep(60 * time.Second)
	}
	fmt.Fprintln(os.Stderr, "fakehang: only --version is supported")
	os.Exit(2)
}
