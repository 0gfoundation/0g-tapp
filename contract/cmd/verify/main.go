// cmd/verify/main.go — verifies TappRegistry contracts on the 0G explorer
// (chainscan-galileo.0g.ai) using the Etherscan-compatible API.
//
// Usage — verify all three contracts via proxy address (recommended):
//
//	go run ./cmd/verify/ --proxy 0x<proxy-addr>
//
// Usage — verify a single contract manually:
//
//	go run ./cmd/verify/ --contract 0x<addr> \
//	  --source src/TappRegistry.sol \
//	  --source-key src/TappRegistry.sol \
//	  --contract-name src/TappRegistry.sol:TappRegistry
package main

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/ethclient"

	"github.com/0gfoundation/0g-tapp/contract/internal/chain"
)

const (
	defaultAPIURL     = "https://chainscan-galileo.0g.ai/open/api"
	defaultRPC        = "https://evmrpc-testnet.0g.ai"
	defaultCompiler   = "v0.8.24+commit.e11b9ed9"
	defaultChainID    = "16602"
	defaultAPIKey     = "00"
)

// beaconSlot is the ERC-1967 storage slot for the beacon address.
var beaconSlot = common.HexToHash("0xa3f0ad74e5423aebfd80d3ef4346578335a9a72aeaee59ff6cb3582b35133d50")

// contractSpec describes a single contract to verify.
type contractSpec struct {
	address      string
	sourcePath   string // path on disk
	sourceKey    string // key in standard-JSON (compiler view)
	contractName string // fully-qualified name
	optimizer    bool   // whether optimizer was enabled at compile time
	runs         int    // optimizer runs
}

func main() {
	proxyAddr    := flag.String("proxy",         "", "BeaconProxy address — auto-discovers all three contracts")
	contractAddr := flag.String("contract",      "", "single contract address (manual mode)")
	apiURL       := flag.String("api",           defaultAPIURL, "Etherscan-compatible API URL")
	rpcURL       := flag.String("rpc",           defaultRPC, "EVM RPC endpoint (used to resolve beacon/impl)")
	sourcePath   := flag.String("source",        "src/TappRegistry.sol", "Solidity source file (manual mode)")
	sourceKey    := flag.String("source-key",    "src/TappRegistry.sol", "source key in standard-JSON (manual mode)")
	contractName := flag.String("contract-name", "src/TappRegistry.sol:TappRegistry", "fully-qualified contract name (manual mode)")
	compilerVer  := flag.String("compiler",      defaultCompiler, "solc compiler version")
	chainID      := flag.String("chain-id",      defaultChainID, "chain ID")
	apiKey       := flag.String("apikey",        defaultAPIKey, "API key")
	flag.Parse()

	if *proxyAddr == "" && *contractAddr == "" {
		fmt.Fprintln(os.Stderr, "error: --proxy or --contract is required")
		os.Exit(1)
	}

	httpClient := &http.Client{Timeout: 60 * time.Second}

	if *contractAddr != "" {
		// ── Manual single-contract mode ────────────────────────────────────────
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
		defer cancel()
		ethClient, err := ethclient.DialContext(ctx, *rpcURL)
		if err != nil {
			fatalf("dial rpc: %v", err)
		}
		spec := contractSpec{
			address:      *contractAddr,
			sourcePath:   *sourcePath,
			sourceKey:    *sourceKey,
			contractName: *contractName,
			optimizer:    true,
			runs:         200,
		}
		verifyOne(httpClient, ethClient, ctx, spec, *apiURL, *compilerVer, *chainID, *apiKey)
		return
	}

	// ── Auto mode: discover impl + beacon + proxy ──────────────────────────────
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	client, err := ethclient.DialContext(ctx, *rpcURL)
	if err != nil {
		fatalf("dial rpc: %v", err)
	}

	proxy := common.HexToAddress(*proxyAddr)

	// Read beacon from proxy ERC-1967 slot.
	raw, err := client.StorageAt(ctx, proxy, beaconSlot, nil)
	if err != nil {
		fatalf("read beacon slot: %v", err)
	}
	beacon := common.BytesToAddress(raw)
	if beacon == (common.Address{}) {
		fatalf("beacon slot is zero — is %s a BeaconProxy?", *proxyAddr)
	}

	// Read impl from beacon.implementation().
	beaconContract, err := chain.NewUpgradeableBeacon(beacon, client)
	if err != nil {
		fatalf("bind beacon: %v", err)
	}
	impl, err := beaconContract.Implementation(&bind.CallOpts{Context: ctx})
	if err != nil {
		fatalf("beacon.implementation(): %v", err)
	}

	fmt.Printf("Proxy   : %s\n", proxy.Hex())
	fmt.Printf("Beacon  : %s\n", beacon.Hex())
	fmt.Printf("Impl    : %s\n\n", impl.Hex())

	contracts := []contractSpec{
		{
			address:      impl.Hex(),
			sourcePath:   "src/TappRegistry.sol",
			sourceKey:    "src/TappRegistry.sol",
			contractName: "src/TappRegistry.sol:TappRegistry",
			optimizer:    true,
			runs:         200,
		},
		{
			address:      beacon.Hex(),
			sourcePath:   "src/proxy/UpgradeableBeacon.sol",
			sourceKey:    "src/proxy/UpgradeableBeacon.sol",
			contractName: "src/proxy/UpgradeableBeacon.sol:UpgradeableBeacon",
			optimizer:    true,
			runs:         200,
		},
		{
			address:      proxy.Hex(),
			sourcePath:   "src/proxy/BeaconProxy.sol",
			sourceKey:    "src/proxy/BeaconProxy.sol",
			contractName: "src/proxy/BeaconProxy.sol:BeaconProxy",
			optimizer:    true,
			runs:         200,
		},
	}

	for _, spec := range contracts {
		fmt.Printf("── %s (%s) ──\n", spec.contractName, spec.address)
		if isVerified(httpClient, spec.address, *apiURL, *apiKey) {
			fmt.Printf("  ✓ Already verified\n\n")
			continue
		}
		verifyOne(httpClient, client, ctx, spec, *apiURL, *compilerVer, *chainID, *apiKey)
		fmt.Println()
	}
}

// isVerified checks whether a contract already has source code on the explorer.
func isVerified(client *http.Client, addr, apiURL, apiKey string) bool {
	u := fmt.Sprintf("%s?module=contract&action=getsourcecode&address=%s&apikey=%s",
		apiURL, addr, apiKey)
	resp, err := client.Get(u)
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)

	var result struct {
		Status string `json:"status"`
		Result []struct {
			SourceCode string `json:"SourceCode"`
		} `json:"result"`
	}
	if json.Unmarshal(body, &result) != nil {
		return false
	}
	if len(result.Result) == 0 {
		return false
	}
	return result.Result[0].SourceCode != ""
}

// constructorArgs fetches the creation bytecode from the explorer, fetches the
// deployed (runtime) bytecode from the chain, finds the runtime bytecode within
// the creation bytecode, and returns everything after it as ABI-encoded constructor args.
func constructorArgs(apiClient *http.Client, ethClient *ethclient.Client, ctx context.Context, addr, apiURL, apiKey string) string {
	// Fetch creation bytecode from explorer.
	u := fmt.Sprintf("%s?module=contract&action=getcontractcreation&contractaddresses=%s&apikey=%s",
		apiURL, addr, apiKey)
	resp, err := apiClient.Get(u)
	if err != nil {
		return ""
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)

	var result struct {
		Result []struct {
			CreationBytecode string `json:"creationBytecode"`
		} `json:"result"`
	}
	if json.Unmarshal(body, &result) != nil || len(result.Result) == 0 {
		return ""
	}
	creationHex := strings.TrimPrefix(result.Result[0].CreationBytecode, "0x")

	// Fetch deployed (runtime) bytecode from chain via eth_getCode.
	code, err := ethClient.CodeAt(ctx, common.HexToAddress(addr), nil)
	if err != nil || len(code) == 0 {
		return ""
	}
	runtimeHex := hex.EncodeToString(code)

	// The creation bytecode is: [init_code containing runtime_bytecode][constructor_args]
	// Find the last occurrence of the runtime bytecode in the creation bytecode.
	idx := strings.LastIndex(creationHex, runtimeHex)
	if idx < 0 {
		return ""
	}
	return creationHex[idx+len(runtimeHex):]
}

// standardJSONInput builds the solc standard-JSON payload for a single source file.
func standardJSONInput(sourceKey, sourceCode string, optimizer bool, runs int) (string, error) {
	input := map[string]any{
		"language": "Solidity",
		"sources": map[string]any{
			sourceKey: map[string]any{
				"content": sourceCode,
			},
		},
		"settings": map[string]any{
			"optimizer": map[string]any{
				"enabled": optimizer,
				"runs":    runs,
			},
			"evmVersion": "cancun",
			"viaIR":      true,
			"outputSelection": map[string]any{
				"*": map[string]any{
					"*": []string{"abi", "evm.bytecode", "evm.deployedBytecode"},
				},
			},
		},
	}
	b, err := json.Marshal(input)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

func verifyOne(httpClient *http.Client, ethClient *ethclient.Client, ctx context.Context, spec contractSpec, apiURL, compilerVer, chainID, apiKey string) {
	addr := strings.ToLower(spec.address)
	if !strings.HasPrefix(addr, "0x") {
		addr = "0x" + addr
	}

	src, err := os.ReadFile(spec.sourcePath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "  read source %s: %v\n", spec.sourcePath, err)
		os.Exit(1)
	}

	stdJSON, err := standardJSONInput(spec.sourceKey, string(src), spec.optimizer, spec.runs)
	if err != nil {
		fmt.Fprintf(os.Stderr, "  build standard JSON: %v\n", err)
		os.Exit(1)
	}

	// Extract constructor args from creation bytecode.
	ctorArgs := constructorArgs(httpClient, ethClient, ctx, addr, apiURL, apiKey)

	fmt.Printf("  Source        : %s\n", spec.sourcePath)
	fmt.Printf("  Contract name : %s\n", spec.contractName)
	fmt.Printf("  Compiler      : %s\n", compilerVer)
	if ctorArgs != "" {
		fmt.Printf("  Constructor   : %s\n", ctorArgs)
	}
	fmt.Printf("  Submitting...\n")

	form := url.Values{}
	form.Set("module",               "contract")
	form.Set("action",               "verifysourcecode")
	form.Set("apikey",               apiKey)
	form.Set("chainid",              chainID)
	form.Set("contractaddress",      addr)
	form.Set("codeformat",           "solidity-standard-json-input")
	form.Set("sourceCode",           stdJSON)
	form.Set("contractname",         spec.contractName)
	form.Set("compilerversion",      compilerVer)
	optimizedStr := "0"
	if spec.optimizer {
		optimizedStr = "1"
	}
	form.Set("optimizationUsed",     optimizedStr)
	form.Set("runs",                 fmt.Sprintf("%d", spec.runs))
	form.Set("constructorArguements", ctorArgs) // Etherscan typo — intentional

	req, err := http.NewRequest(http.MethodPost, apiURL, strings.NewReader(form.Encode()))
	if err != nil {
		fmt.Fprintf(os.Stderr, "  build request: %v\n", err)
		os.Exit(1)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	resp, err := httpClient.Do(req)
	if err != nil {
		fmt.Fprintf(os.Stderr, "  POST: %v\n", err)
		os.Exit(1)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)

	var result struct {
		Status  string `json:"status"`
		Message string `json:"message"`
		Result  string `json:"result"`
	}
	if json.Unmarshal(body, &result) != nil {
		fmt.Fprintf(os.Stderr, "  unexpected response: %s\n", body)
		os.Exit(1)
	}

	lower := strings.ToLower(result.Result + result.Message)
	switch {
	case result.Status == "1":
		fmt.Printf("  Submitted (GUID: %s)\n", result.Result)
		guid := result.Result
		// Poll for result.
		for i := 0; i < 12; i++ {
			time.Sleep(5 * time.Second)
			status := pollVerify(httpClient, guid, apiURL, apiKey)
			if status == "pending" {
				fmt.Printf("  Pending...\n")
				continue
			}
			if strings.Contains(strings.ToLower(status), "pass") {
				fmt.Printf("  ✓ Verified: %s\n", status)
				fmt.Printf("    https://chainscan-galileo.0g.ai/address/%s#code\n", addr)
			} else {
				fmt.Fprintf(os.Stderr, "  ✗ Failed: %s\n", status)
			}
			return
		}
		fmt.Printf("  Timed out polling — check manually:\n")
		fmt.Printf("    curl '%s?module=contract&action=checkverifystatus&guid=%s&apikey=%s'\n",
			apiURL, guid, apiKey)
	case strings.Contains(lower, "already"):
		fmt.Printf("  ✓ Already verified\n")
		fmt.Printf("    https://chainscan-galileo.0g.ai/address/%s#code\n", addr)
	default:
		fmt.Fprintf(os.Stderr, "  ✗ Failed: [%s] %s\n", result.Status, result.Result)
	}

}

func pollVerify(client *http.Client, guid, apiURL, apiKey string) string {
	u := fmt.Sprintf("%s?module=contract&action=checkverifystatus&guid=%s&apikey=%s",
		apiURL, guid, apiKey)
	resp, err := client.Get(u)
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
	if strings.Contains(lower, "pending") || strings.Contains(lower, "0") {
		return "pending"
	}
	return result.Result
}

func fatalf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "error: "+format+"\n", args...)
	os.Exit(1)
}
