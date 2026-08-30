// Command credenshare-conformance verifies an installed copy of the SDK against the
// packaged wire-specification vectors.
//
//	go run github.com/CredenShare/credenshare-sdk-go/cmd/credenshare-conformance@latest
//	credenshare-conformance -v
//
// It exits non-zero on any failure, so it works as a deployment gate. Worth running in the
// environment that will actually do the encrypting: a client that fails these produces content
// nothing else can read, and that failure is otherwise invisible until somebody opens a link.
package main

import (
	"crypto/sha256"
	"encoding/hex"
	"flag"
	"fmt"
	"os"
	"strings"

	credenshare "github.com/CredenShare/credenshare-sdk-go"
)

func main() {
	verbose := flag.Bool("v", false, "print one line per vector")
	flag.Parse()

	digest := sha256.Sum256(credenshare.ConformanceVectorsJSON())
	fmt.Printf("CredenShare conformance vectors v%d\n", credenshare.SupportedVectorsVersion)
	fmt.Printf("  sha256:%s\n\n", hex.EncodeToString(digest[:]))

	passed, failures, err := credenshare.RunConformance(*verbose, func(line string) {
		fmt.Println(line)
	})
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	if *verbose {
		fmt.Println()
	}

	if len(failures) == 0 {
		fmt.Printf("%d passed. This installation conforms to the wire specification.\n", passed)
		return
	}

	for _, failure := range failures {
		fmt.Fprintln(os.Stderr, "FAIL "+failure.Name)
		for _, line := range strings.Split(failure.Reason, "\n") {
			fmt.Fprintln(os.Stderr, "     "+line)
		}
	}
	fmt.Fprintf(os.Stderr, "\n%d passed, %d FAILED\n", passed, len(failures))
	fmt.Fprintln(os.Stderr,
		"This installation does not implement the wire specification correctly. Content it "+
			"encrypts may be unreadable by every other client, including the web application.")
	os.Exit(1)
}
