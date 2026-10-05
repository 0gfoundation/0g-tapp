// cmd/verify/main.go — verifies TappRegistry contracts on the 0G explorer
// (chainscan-galileo.0g.ai / chainscan.0g.ai) using the Etherscan-compatible API.
// No key, no gas: it only talks to the explorer and reads the chain.
//
// Usage — verify all three contracts behind the network's registry (recommended;
// run it again after an upgrade and it verifies the new implementation):
//
//	go run ./cmd/verify/ --network testnet|mainnet [--proxy 0x<proxy-addr>]
//
// Usage — verify a single contract manually:
//
//	go run ./cmd/verify/ --network testnet --contract 0x<addr> \
//	  --source src/TappRegistry.sol \
//	  --source-key src/TappRegistry.sol \
//	  --contract-name src/TappRegistry.sol:TappRegistry
//
// cmd/deploy and cmd/upgrade do the same under --verify.
package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/ethereum/go-ethereum/common"

	"github.com/0gfoundation/0g-tapp/contract/cmd/internal/explorer"
	reg "github.com/0gfoundation/0g-tapp/contract/cmd/internal/registry"
)

func main() {
	netFlags := reg.RegisterNetworkFlags(flag.CommandLine)
	proxyAddr := flag.String("proxy", "", "BeaconProxy address — auto-discovers all three contracts (default: the network's registry)")
	contractAddr := flag.String("contract", "", "single contract address (manual mode)")
	sourcePath := flag.String("source", "src/TappRegistry.sol", "Solidity source file (manual mode)")
	sourceKey := flag.String("source-key", "src/TappRegistry.sol", "source key in standard-JSON (manual mode)")
	contractName := flag.String("contract-name", "src/TappRegistry.sol:TappRegistry", "fully-qualified contract name (manual mode)")
	compiler := flag.String("compiler", explorer.DefaultCompiler, "solc compiler version")
	apiKey := flag.String("apikey", explorer.DefaultAPIKey, "API key")
	flag.Parse()

	n, err := netFlags.Resolve()
	if err != nil {
		reg.Fatalf("%v", err)
	}
	ctx, cancel := reg.Ctx()
	defer cancel()
	c, err := reg.Dial(ctx, n)
	if err != nil {
		reg.Fatalf("%v", err)
	}
	v := explorer.New(n, c)
	v.Compiler, v.APIKey = *compiler, *apiKey

	if *contractAddr != "" {
		s := explorer.Spec{
			Address:      common.HexToAddress(*contractAddr),
			SourcePath:   *sourcePath,
			SourceKey:    *sourceKey,
			ContractName: *contractName,
			Optimizer:    true,
			Runs:         200,
		}
		if v.All(ctx, s) > 0 {
			os.Exit(1)
		}
		return
	}

	if *proxyAddr == "" {
		*proxyAddr = n.Proxy
	}
	proxy := common.HexToAddress(*proxyAddr)
	beacon, err := reg.BeaconOf(ctx, c, proxy)
	if err != nil {
		reg.Fatalf("%v", err)
	}
	beaconArtifact, err := reg.LoadArtifact("UpgradeableBeacon.sol", "UpgradeableBeacon")
	if err != nil {
		reg.Fatalf("%v", err)
	}
	out, err := reg.Call(ctx, c, beaconArtifact.ABI, beacon, common.Address{}, "implementation")
	if err != nil {
		reg.Fatalf("beacon.implementation(): %v", err)
	}
	impl := out[0].(common.Address)

	fmt.Printf("Proxy   : %s\nBeacon  : %s\nImpl    : %s\n\n", proxy.Hex(), beacon.Hex(), impl.Hex())
	if v.All(ctx, explorer.Implementation(impl), explorer.Beacon(beacon), explorer.Proxy(proxy)) > 0 {
		os.Exit(1)
	}
}
