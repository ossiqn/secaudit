package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"secaudit/internal/scanner"
)

func main() {
	domain := flag.String("domain", "", "target domain")
	own := flag.Bool("i-own-this-domain", false, "confirm you own this domain")
	flag.Parse()

	if *domain == "" {
		fmt.Fprintln(os.Stderr, "usage: scan -domain example.com -i-own-this-domain")
		os.Exit(1)
	}

	if !*own {
		fmt.Fprintln(os.Stderr, "error: you must confirm domain ownership with -i-own-this-domain flag")
		fmt.Fprintln(os.Stderr, "this tool should only be used on domains you own or have permission to test")
		os.Exit(1)
	}

	fmt.Fprintf(os.Stderr, "scanning %s ...\n", *domain)

	report, err := scanner.RunFullScan(*domain)
	if err != nil {
		fmt.Fprintf(os.Stderr, "scan failed: %v\n", err)
		os.Exit(1)
	}

	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	enc.Encode(report)
}