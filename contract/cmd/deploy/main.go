// cmd/deploy/main.go — deploys the TappRegistry beacon-proxy stack.
//
// Three-step deploy:
//  1. Deploy TappRegistry implementation (no constructor args)
//  2. Deploy UpgradeableBeacon(impl, deployer)
//  3. Deploy BeaconProxy(beacon, initialize(minStakeAmount, lockPeriod))
//
// Usage:
//
//	go run ./cmd/deploy/ \
//	  --rpc      https://evmrpc-testnet.0g.ai \
//	  --key      0x<private-key>              \
//	  --chain-id 16602                        \
//	  --stake    1000000000000000000          \
//	  --lock     86400
package main

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"math/big"
	"os"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethclient"

	"github.com/0gfoundation/0g-tapp/contract/internal/chain"
)

func main() {
	rpcURL   := flag.String("rpc",      "https://evmrpc-testnet.0g.ai", "EVM RPC endpoint")
	keyHex   := flag.String("key",      "", "deployer private key (hex, with or without 0x)")
	chainID  := flag.Int64("chain-id",  16602, "chain ID")
	stake    := flag.String("stake",    "1000000000000000000", "minStakeAmount in wei (default 1 OG)")
	lock     := flag.Int64("lock",      86400, "lockPeriod in seconds (default 1 day)")
	flag.Parse()

	if *keyHex == "" {
		fmt.Fprintln(os.Stderr, "error: --key is required")
		os.Exit(1)
	}

	privKey, err := crypto.HexToECDSA(strings.TrimPrefix(*keyHex, "0x"))
	if err != nil {
		fmt.Fprintf(os.Stderr, "parse key: %v\n", err)
		os.Exit(1)
	}
	deployer := crypto.PubkeyToAddress(privKey.PublicKey)
	fmt.Printf("Deployer : %s\n", deployer.Hex())

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	client, err := ethclient.DialContext(ctx, *rpcURL)
	if err != nil {
		fmt.Fprintf(os.Stderr, "dial rpc: %v\n", err)
		os.Exit(1)
	}

	auth, err := bind.NewKeyedTransactorWithChainID(privKey, big.NewInt(*chainID))
	if err != nil {
		fmt.Fprintf(os.Stderr, "transactor: %v\n", err)
		os.Exit(1)
	}
	auth.Context = ctx

	minStake := new(big.Int)
	if _, ok := minStake.SetString(*stake, 10); !ok {
		fmt.Fprintf(os.Stderr, "invalid stake: %s\n", *stake)
		os.Exit(1)
	}
	lockPeriod := big.NewInt(*lock)

	loadBytecode := func(artifactPath string) []byte {
		raw, err := os.ReadFile(artifactPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "read artifact %s: %v\n", artifactPath, err)
			os.Exit(1)
		}
		var artifact struct {
			Bytecode struct {
				Object string `json:"object"`
			} `json:"bytecode"`
		}
		if err := json.Unmarshal(raw, &artifact); err != nil {
			fmt.Fprintf(os.Stderr, "parse artifact %s: %v\n", artifactPath, err)
			os.Exit(1)
		}
		b, err := hex.DecodeString(strings.TrimPrefix(artifact.Bytecode.Object, "0x"))
		if err != nil {
			fmt.Fprintf(os.Stderr, "decode bytecode: %v\n", err)
			os.Exit(1)
		}
		return b
	}

	// ── Step 1: Deploy TappRegistry implementation ────────────────────────────
	fmt.Printf("\n[1/3] Deploying TappRegistry implementation (chainID=%d)...\n", *chainID)

	implABI, err := abi.JSON(strings.NewReader(chain.TappRegistryMetaData.ABI))
	if err != nil {
		fmt.Fprintf(os.Stderr, "parse TappRegistry ABI: %v\n", err)
		os.Exit(1)
	}
	implBytecode := loadBytecode("out/TappRegistry.sol/TappRegistry.json")

	implAddr, implTx, _, err := bind.DeployContract(auth, implABI, implBytecode, client)
	if err != nil {
		fmt.Fprintf(os.Stderr, "deploy impl: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("  Tx hash : %s\n", implTx.Hash().Hex())
	implReceipt, err := bind.WaitMined(ctx, client, implTx)
	if err != nil || implReceipt.Status == 0 {
		fmt.Fprintln(os.Stderr, "impl deploy failed")
		os.Exit(1)
	}
	fmt.Printf("  Impl    : %s\n", implAddr.Hex())

	// ── Step 2: Deploy UpgradeableBeacon ─────────────────────────────────────
	fmt.Printf("\n[2/3] Deploying UpgradeableBeacon(impl=%s, owner=%s)...\n", implAddr.Hex(), deployer.Hex())

	beaconABI, err := abi.JSON(strings.NewReader(chain.UpgradeableBeaconMetaData.ABI))
	if err != nil {
		fmt.Fprintf(os.Stderr, "parse UpgradeableBeacon ABI: %v\n", err)
		os.Exit(1)
	}
	beaconBytecode := loadBytecode("out/UpgradeableBeacon.sol/UpgradeableBeacon.json")

	beaconAddr, beaconTx, _, err := bind.DeployContract(auth, beaconABI, beaconBytecode, client, implAddr, deployer)
	if err != nil {
		fmt.Fprintf(os.Stderr, "deploy beacon: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("  Tx hash : %s\n", beaconTx.Hash().Hex())
	beaconReceipt, err := bind.WaitMined(ctx, client, beaconTx)
	if err != nil || beaconReceipt.Status == 0 {
		fmt.Fprintln(os.Stderr, "beacon deploy failed")
		os.Exit(1)
	}
	fmt.Printf("  Beacon  : %s\n", beaconAddr.Hex())

	// ── Step 3: Deploy BeaconProxy ────────────────────────────────────────────
	fmt.Printf("\n[3/3] Deploying BeaconProxy(beacon=%s, stake=%s, lock=%d)...\n",
		beaconAddr.Hex(), minStake, *lock)

	initCalldata, err := implABI.Pack("initialize", minStake, lockPeriod)
	if err != nil {
		fmt.Fprintf(os.Stderr, "pack initialize: %v\n", err)
		os.Exit(1)
	}

	proxyConstructorABI, _ := abi.JSON(strings.NewReader(`[{
		"type": "constructor",
		"inputs": [
			{"name": "beacon", "type": "address"},
			{"name": "data",   "type": "bytes"}
		],
		"stateMutability": "payable"
	}]`))
	proxyBytecode := loadBytecode("out/BeaconProxy.sol/BeaconProxy.json")

	proxyAddr, proxyTx, _, err := bind.DeployContract(auth, proxyConstructorABI, proxyBytecode, client,
		beaconAddr, initCalldata)
	if err != nil {
		fmt.Fprintf(os.Stderr, "deploy proxy: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("  Tx hash : %s\n", proxyTx.Hash().Hex())
	proxyReceipt, err := bind.WaitMined(ctx, client, proxyTx)
	if err != nil || proxyReceipt.Status == 0 {
		fmt.Fprintln(os.Stderr, "proxy deploy failed")
		os.Exit(1)
	}
	fmt.Printf("  Proxy   : %s\n", proxyAddr.Hex())

	fmt.Printf(`
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
DEPLOY COMPLETE
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Implementation : %s
Beacon         : %s
Proxy (stable) : %s
minStakeAmount : %s wei
lockPeriod     : %d seconds

Explorer (proxy):
  https://chainscan-galileo.0g.ai/address/%s
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
`, implAddr.Hex(), beaconAddr.Hex(), proxyAddr.Hex(),
		minStake.String(), *lock, proxyAddr.Hex())
}
