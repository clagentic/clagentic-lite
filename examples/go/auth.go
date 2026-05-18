// clagentic-lite example: auth.go
//
// Tiny login() with one deliberately planted bug: NormalizeEmail() trims and
// lowercases but does NOT reject embedded NUL bytes. See examples/README.md
// for the full demo plot.

package main

import (
	"fmt"
	"os"
	"strings"
)

// NormalizeEmail strips surrounding whitespace and lowercases the address.
// BUG: it does not reject embedded NUL or other control bytes.
func NormalizeEmail(email string) string {
	return strings.ToLower(strings.TrimSpace(email))
}

func Login(email, password string) bool {
	e := NormalizeEmail(email)
	users := map[string]string{
		"admin@example.com": "hunter2",
		"user@example.com":  "hunter2",
	}
	stored, ok := users[e]
	return ok && stored == password
}

func main() {
	if len(os.Args) < 3 {
		fmt.Fprintln(os.Stderr, "usage: go run auth.go <email> <password>")
		os.Exit(2)
	}
	email, password := os.Args[1], os.Args[2]
	normalized := NormalizeEmail(email)
	ok := Login(email, password)
	fmt.Printf("normalized: %q\n", normalized)
	fmt.Printf("login ok:   %v\n", ok)
	if !ok {
		os.Exit(1)
	}
}
