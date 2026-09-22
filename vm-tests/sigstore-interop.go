// Independent bundle verifier for the private VM tests. It uses upstream
// sigstore-go, not laut's parser, PAE, signature, checkpoint, or Merkle code.
package main

import (
	"bufio"
	"crypto/ed25519"
	"encoding/base64"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/secure-systems-lab/go-securesystemslib/dsse"
	"github.com/sigstore/sigstore-go/pkg/bundle"
	"github.com/sigstore/sigstore-go/pkg/root"
	"github.com/sigstore/sigstore-go/pkg/verify"
	"github.com/sigstore/sigstore/pkg/signature"
	"github.com/sigstore/sigstore/pkg/signature/options"
)

func run() error {
	if len(os.Args) != 5 {
		return fmt.Errorf("usage: laut-interop ROOT BUNDLES NIX-PUBLIC-KEY direct|logged")
	}
	trusted, err := root.NewTrustedRootFromPath(os.Args[1])
	if err != nil {
		return err
	}
	raw, err := os.ReadFile(os.Args[3])
	if err != nil {
		return err
	}
	_, b64, ok := strings.Cut(strings.TrimSpace(string(raw)), ":")
	if !ok {
		return fmt.Errorf("invalid Nix key")
	}
	key, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return err
	}
	if len(key) != ed25519.PublicKeySize {
		return fmt.Errorf("invalid public key length")
	}
	pk := ed25519.PublicKey(key)
	hint, err := dsse.SHA256KeyID(pk)
	if err != nil {
		return err
	}
	sv, err := signature.LoadVerifierWithOpts(pk, options.WithED25519ph())
	if err != nil {
		return err
	}
	material := root.NewTrustedPublicKeyMaterialFromMapping(map[string]*root.ExpiringKey{
		hint: root.NewExpiringKey(sv, time.Time{}, time.Time{}),
	})
	opts := []verify.VerifierOption{verify.WithNoObserverTimestamps()}
	switch os.Args[4] {
	case "logged":
		opts = append(opts, verify.WithTransparencyLog(1))
	case "direct":
	default:
		return fmt.Errorf("unknown mode")
	}
	verifier, err := verify.NewVerifier(root.TrustedMaterialCollection{trusted, material}, opts...)
	if err != nil {
		return err
	}
	file, err := os.Open(os.Args[2])
	if err != nil {
		return err
	}
	defer file.Close()
	lines := bufio.NewScanner(file)
	lines.Buffer(make([]byte, 4096), 64<<20)
	count := 0
	for lines.Scan() {
		if len(strings.TrimSpace(lines.Text())) == 0 {
			continue
		}
		b := new(bundle.Bundle)
		if err := b.UnmarshalJSON(lines.Bytes()); err != nil {
			return err
		}
		// Laut discovers outputs from an input hash, rather than matching an
		// already-known artifact. This oracle checks the envelope and evidence;
		// the Rust orchestrator separately enforces the input/output profile.
		if _, err := verifier.Verify(b, verify.NewPolicy(verify.WithoutArtifactUnsafe(), verify.WithKey())); err != nil {
			return err
		}
		count++
	}
	if err := lines.Err(); err != nil {
		return err
	}
	if count == 0 {
		return fmt.Errorf("no bundles")
	}
	fmt.Printf("independently verified %d bundles\n", count)
	return nil
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
