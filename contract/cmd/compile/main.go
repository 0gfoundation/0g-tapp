// cmd/compile/main.go — compiles TappRegistry contracts via Docker (foundry).
//
// Requires Docker. Runs forge build inside the foundry container, then
// extracts ABIs from the build artifacts.
//
// Usage:
//
//	go run ./cmd/compile/
package main

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
)

func main() {
	// Resolve project root (directory containing this binary's go.mod)
	root, err := filepath.Abs(".")
	if err != nil {
		fatalf("resolve root: %v", err)
	}

	// ── Step 1: forge build via Docker ────────────────────────────────────────
	fmt.Println("[1/2] Compiling contracts with forge (via Docker)...")

	cmd := exec.Command("docker", "run", "--rm",
		"-v", root+":/contracts",
		"--entrypoint", "forge",
		"ghcr.io/foundry-rs/foundry:latest",
		"build", "--root", "/contracts",
	)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		fatalf("forge build: %v", err)
	}

	// ── Step 2: extract ABIs ──────────────────────────────────────────────────
	fmt.Println("\n[2/2] Extracting ABIs...")

	abiDir := filepath.Join(root, "internal", "chain", "abi")
	if err := os.MkdirAll(abiDir, 0755); err != nil {
		fatalf("mkdir abi: %v", err)
	}

	extract := []struct {
		artifact string
		out      string
	}{
		{"out/TappRegistry.sol/TappRegistry.json", "internal/chain/abi/TappRegistry.json"},
		{"out/UpgradeableBeacon.sol/UpgradeableBeacon.json", "internal/chain/abi/UpgradeableBeacon.json"},
		{"out/BeaconProxy.sol/BeaconProxy.json", "internal/chain/abi/BeaconProxy.json"},
	}

	for _, e := range extract {
		raw, err := os.ReadFile(filepath.Join(root, e.artifact))
		if err != nil {
			fatalf("read %s: %v", e.artifact, err)
		}
		var artifact struct {
			ABI json.RawMessage `json:"abi"`
		}
		if err := json.Unmarshal(raw, &artifact); err != nil {
			fatalf("parse %s: %v", e.artifact, err)
		}
		pretty, _ := json.MarshalIndent(artifact.ABI, "", "  ")
		if err := os.WriteFile(filepath.Join(root, e.out), pretty, 0644); err != nil {
			fatalf("write %s: %v", e.out, err)
		}
		fmt.Printf("  ✓ %s\n", e.out)
	}

	fmt.Printf(`
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
COMPILE COMPLETE
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Artifacts : out/
ABIs      : internal/chain/abi/

Next: regenerate Go bindings if ABI changed:
  abigen --abi internal/chain/abi/TappRegistry.json \
         --pkg chain --type TappRegistry \
         --out internal/chain/tapp_registry.go
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
`)
}

func fatalf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "error: "+format+"\n", args...)
	os.Exit(1)
}
