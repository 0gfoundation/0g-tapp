// Package explorer verifies contract source on the 0G explorers through their
// Etherscan-compatible API. Shared by cmd/verify, and by cmd/deploy and
// cmd/upgrade under --verify.
package explorer

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/ethclient"

	reg "github.com/0gfoundation/0g-tapp/contract/cmd/internal/registry"
)

const (
	DefaultCompiler = "v0.8.24+commit.e11b9ed9"
	DefaultAPIKey   = "00"
)

// Spec describes one contract to verify.
type Spec struct {
	Address      common.Address
	SourcePath   string // path on disk
	SourceKey    string // key in standard-JSON (compiler view)
	ContractName string // fully-qualified name
	Optimizer    bool   // whether optimizer was enabled at compile time
	Runs         int    // optimizer runs
}

func spec(addr common.Address, file, name string) Spec {
	return Spec{Address: addr, SourcePath: file, SourceKey: file, ContractName: file + ":" + name, Optimizer: true, Runs: 200}
}

// Implementation, Beacon and Proxy are the registry's three contracts.
func Implementation(a common.Address) Spec {
	return spec(a, "src/TappRegistry.sol", "TappRegistry")
}
func Beacon(a common.Address) Spec {
	return spec(a, "src/proxy/UpgradeableBeacon.sol", "UpgradeableBeacon")
}
func Proxy(a common.Address) Spec { return spec(a, "src/proxy/BeaconProxy.sol", "BeaconProxy") }

// Verifier talks to one network's explorer.
type Verifier struct {
	Net      reg.Network
	Eth      *ethclient.Client
	Compiler string
	APIKey   string
	http     *http.Client
}

func New(n reg.Network, eth *ethclient.Client) *Verifier {
	return &Verifier{Net: n, Eth: eth, Compiler: DefaultCompiler, APIKey: DefaultAPIKey,
		http: &http.Client{Timeout: 60 * time.Second}}
}

// All verifies each spec, skipping what is already verified. It reports per
// contract and returns how many failed — a failure here never undoes a deploy
// or an upgrade, so the caller decides what it means.
func (v *Verifier) All(ctx context.Context, specs ...Spec) int {
	failed := 0
	for _, s := range specs {
		fmt.Printf("── %s (%s) ──\n", s.ContractName, s.Address.Hex())
		if err := v.One(ctx, s); err != nil {
			fmt.Fprintf(os.Stderr, "  ✗ %v\n", err)
			failed++
		}
		fmt.Println()
	}
	return failed
}

// One verifies a single contract. A contract deployed seconds ago may not be
// indexed yet — its creation bytecode, needed for the constructor arguments, is
// then missing — so it waits for the explorer first.
func (v *Verifier) One(ctx context.Context, s Spec) error {
	addr := strings.ToLower(s.Address.Hex())
	if v.isVerified(addr) {
		fmt.Printf("  ✓ Already verified\n    %s/address/%s#code\n", v.Net.Explorer, addr)
		return nil
	}

	src, err := os.ReadFile(s.SourcePath)
	if err != nil {
		return fmt.Errorf("read source %s: %w", s.SourcePath, err)
	}
	stdJSON, err := standardJSONInput(s.SourceKey, string(src), s.Optimizer, s.Runs)
	if err != nil {
		return fmt.Errorf("build standard JSON: %w", err)
	}

	ctorArgs, err := v.waitForCreation(ctx, addr)
	if err != nil {
		return err
	}

	fmt.Printf("  Source        : %s\n", s.SourcePath)
	fmt.Printf("  Contract name : %s\n", s.ContractName)
	fmt.Printf("  Compiler      : %s\n", v.Compiler)
	fmt.Printf("  Submitting...\n")

	optimized := "0"
	if s.Optimizer {
		optimized = "1"
	}
	form := url.Values{}
	form.Set("module", "contract")
	form.Set("action", "verifysourcecode")
	form.Set("apikey", v.APIKey)
	form.Set("chainid", fmt.Sprintf("%d", v.Net.ChainID))
	form.Set("contractaddress", addr)
	form.Set("codeformat", "solidity-standard-json-input")
	form.Set("sourceCode", stdJSON)
	form.Set("contractname", s.ContractName)
	form.Set("compilerversion", v.Compiler)
	form.Set("optimizationUsed", optimized)
	form.Set("runs", fmt.Sprintf("%d", s.Runs))
	form.Set("constructorArguements", ctorArgs) // Etherscan typo — intentional

	req, err := http.NewRequest(http.MethodPost, v.Net.ExplorerAPI, strings.NewReader(form.Encode()))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	resp, err := v.http.Do(req)
	if err != nil {
		return fmt.Errorf("POST: %w", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)

	var result struct {
		Status  string `json:"status"`
		Message string `json:"message"`
		Result  string `json:"result"`
	}
	if json.Unmarshal(body, &result) != nil {
		return fmt.Errorf("unexpected response: %s", body)
	}
	if strings.Contains(strings.ToLower(result.Result+result.Message), "already") {
		fmt.Printf("  ✓ Already verified\n    %s/address/%s#code\n", v.Net.Explorer, addr)
		return nil
	}
	if result.Status != "1" {
		return fmt.Errorf("refused: [%s] %s", result.Status, result.Result)
	}

	guid := result.Result
	fmt.Printf("  Submitted (GUID: %s)\n", guid)
	for i := 0; i < 24; i++ {
		time.Sleep(5 * time.Second)
		status := v.poll(guid)
		if status == "pending" {
			fmt.Printf("  Pending...\n")
			continue
		}
		if strings.Contains(strings.ToLower(status), "pass") {
			fmt.Printf("  ✓ Verified: %s\n    %s/address/%s#code\n", status, v.Net.Explorer, addr)
			return nil
		}
		return fmt.Errorf("failed: %s", status)
	}
	return fmt.Errorf("timed out polling — check: curl '%s?module=contract&action=checkverifystatus&guid=%s&apikey=%s'",
		v.Net.ExplorerAPI, guid, v.APIKey)
}

// waitForCreation returns the ABI-encoded constructor arguments, waiting (up to
// a few minutes) for the explorer to index a freshly deployed contract.
func (v *Verifier) waitForCreation(ctx context.Context, addr string) (string, error) {
	for i := 0; ; i++ {
		args, indexed := v.constructorArgs(ctx, addr)
		if indexed {
			if args != "" {
				fmt.Printf("  Constructor   : %s\n", args)
			}
			return args, nil
		}
		if i == 0 {
			fmt.Printf("  Waiting for the explorer to index %s...\n", addr)
		}
		if i >= 36 {
			return "", fmt.Errorf("the explorer has not indexed %s after 3 minutes; run cmd/verify again later", addr)
		}
		time.Sleep(5 * time.Second)
	}
}

// isVerified checks whether a contract already has source code on the explorer.
func (v *Verifier) isVerified(addr string) bool {
	u := fmt.Sprintf("%s?module=contract&action=getsourcecode&address=%s&apikey=%s", v.Net.ExplorerAPI, addr, v.APIKey)
	resp, err := v.http.Get(u)
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	var result struct {
		Result []struct {
			SourceCode string `json:"SourceCode"`
		} `json:"result"`
	}
	if json.Unmarshal(body, &result) != nil || len(result.Result) == 0 {
		return false
	}
	return result.Result[0].SourceCode != ""
}

// constructorArgs fetches the creation bytecode from the explorer and the
// runtime bytecode from the chain; the constructor arguments are what follows
// the runtime bytecode inside the creation bytecode. indexed is false while the
// explorer does not know the contract yet.
func (v *Verifier) constructorArgs(ctx context.Context, addr string) (args string, indexed bool) {
	u := fmt.Sprintf("%s?module=contract&action=getcontractcreation&contractaddresses=%s&apikey=%s", v.Net.ExplorerAPI, addr, v.APIKey)
	resp, err := v.http.Get(u)
	if err != nil {
		return "", false
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	var result struct {
		Result []struct {
			CreationBytecode string `json:"creationBytecode"`
		} `json:"result"`
	}
	if json.Unmarshal(body, &result) != nil || len(result.Result) == 0 || result.Result[0].CreationBytecode == "" {
		return "", false
	}
	creationHex := strings.TrimPrefix(result.Result[0].CreationBytecode, "0x")

	code, err := v.Eth.CodeAt(ctx, common.HexToAddress(addr), nil)
	if err != nil || len(code) == 0 {
		return "", false
	}
	runtimeHex := hex.EncodeToString(code)
	idx := strings.LastIndex(creationHex, runtimeHex)
	if idx < 0 {
		return "", true
	}
	return creationHex[idx+len(runtimeHex):], true
}

// standardJSONInput builds the solc standard-JSON payload for a single source
// file, with the settings foundry.toml compiles under.
func standardJSONInput(sourceKey, sourceCode string, optimizer bool, runs int) (string, error) {
	input := map[string]any{
		"language": "Solidity",
		"sources": map[string]any{
			sourceKey: map[string]any{"content": sourceCode},
		},
		"settings": map[string]any{
			"optimizer":  map[string]any{"enabled": optimizer, "runs": runs},
			"evmVersion": "cancun",
			"viaIR":      true,
			"outputSelection": map[string]any{
				"*": map[string]any{"*": []string{"abi", "evm.bytecode", "evm.deployedBytecode"}},
			},
		},
	}
	b, err := json.Marshal(input)
	return string(b), err
}

func (v *Verifier) poll(guid string) string {
	u := fmt.Sprintf("%s?module=contract&action=checkverifystatus&guid=%s&apikey=%s", v.Net.ExplorerAPI, guid, v.APIKey)
	resp, err := v.http.Get(u)
	if err != nil {
		return "pending"
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	var result struct {
		Result string `json:"result"`
	}
	if json.Unmarshal(body, &result) != nil {
		return "pending"
	}
	lower := strings.ToLower(result.Result)
	if strings.Contains(lower, "pending") || strings.Contains(lower, "queue") || lower == "0" {
		return "pending"
	}
	return result.Result
}
