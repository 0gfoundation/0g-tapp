// cmd/deploy — deploys a new TappRegistry: implementation, UpgradeableBeacon,
// BeaconProxy (initialised), then hands the authority off the deploy key.
//
// Run `forge build` in contract/ first. Usage:
//
//	PRIVATE_KEY=0x<throwaway> go run ./cmd/deploy/ --network testnet \
//	  --stake 1000000000000000000 --lock 86400 \
//	  [--beacon-owner 0x<timelock|wallet>] [--admin 0x<wallet>] [--verify]
//
// The deploy key needs gas and nothing else. It starts out owning the beacon
// (upgrades) and being the registry admin (stake parameters); --beacon-owner and
// --admin move both away as soon as the contracts exist. On mainnet both are
// REQUIRED: a deploy key left holding them is a key that can replace the
// registry's code. Point --beacon-owner at the timelock there.
package main

import (
	"flag"
	"fmt"
	"math/big"
	"os"

	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/common"

	"github.com/0gfoundation/0g-tapp/contract/cmd/internal/explorer"
	reg "github.com/0gfoundation/0g-tapp/contract/cmd/internal/registry"
)

func main() {
	fs := flag.NewFlagSet("deploy", flag.ExitOnError)
	netFlags := reg.RegisterNetworkFlags(fs)
	keyFlags := reg.RegisterKeyFlags(fs)
	stake := fs.String("stake", "1000000000000000000", "minStakeAmount in wei")
	lock := fs.Int64("lock", 86400, "lockPeriod in seconds")
	beaconOwner := fs.String("beacon-owner", "", "who may upgrade (the timelock on mainnet); default: keep the deploy key")
	admin := fs.String("admin", "", "registry admin (stake parameters); default: keep the deploy key")
	verify := fs.Bool("verify", false, "verify the three contracts on the explorer once deployed")
	_ = fs.Parse(os.Args[1:])

	n, err := netFlags.Resolve()
	if err != nil {
		reg.Fatalf("%v", err)
	}
	if n.RequireAuthorityHandoff && (*beaconOwner == "" || *admin == "") {
		reg.Fatalf("--network %s requires --beacon-owner and --admin: the deploy key must not keep the power to replace the registry's code", n.Name)
	}
	for name, v := range map[string]string{"--beacon-owner": *beaconOwner, "--admin": *admin} {
		if v != "" && !common.IsHexAddress(v) {
			reg.Fatalf("%s is not an address: %s", name, v)
		}
	}
	minStake, ok := new(big.Int).SetString(*stake, 10)
	if !ok {
		reg.Fatalf("invalid --stake: %s", *stake)
	}

	key, err := keyFlags.Load()
	if err != nil {
		reg.Fatalf("%v", err)
	}
	deployer := reg.Address(key)

	ctx, cancel := reg.Ctx()
	defer cancel()
	c, err := reg.Dial(ctx, n)
	if err != nil {
		reg.Fatalf("%v", err)
	}
	auth, err := reg.Transactor(ctx, c, key, n.ChainID)
	if err != nil {
		reg.Fatalf("%v", err)
	}

	impl, err := reg.LoadArtifact("TappRegistry.sol", "TappRegistry")
	if err != nil {
		reg.Fatalf("%v", err)
	}
	beacon, err := reg.LoadArtifact("UpgradeableBeacon.sol", "UpgradeableBeacon")
	if err != nil {
		reg.Fatalf("%v", err)
	}
	proxy, err := reg.LoadArtifact("BeaconProxy.sol", "BeaconProxy")
	if err != nil {
		reg.Fatalf("%v", err)
	}

	fmt.Printf("Network  : %s (chain %d)\nDeployer : %s\n", n.Name, n.ChainID, deployer.Hex())

	deploy := func(label string, a reg.Artifact, args ...any) common.Address {
		addr, tx, _, err := bind.DeployContract(auth, a.ABI, a.Bytecode, c, args...)
		if err != nil {
			reg.Fatalf("deploy %s: %v", label, err)
		}
		if _, err := reg.Mined(ctx, c, tx, "deploy "+label); err != nil {
			reg.Fatalf("%v", err)
		}
		fmt.Printf("  %-14s %s\n", label, addr.Hex())
		return addr
	}

	fmt.Println("\n[1/4] contracts")
	implAddr := deploy("implementation", impl)
	beaconAddr := deploy("beacon", beacon, implAddr, deployer)
	initData, err := impl.ABI.Pack("initialize", minStake, big.NewInt(*lock))
	if err != nil {
		reg.Fatalf("pack initialize: %v", err)
	}
	proxyAddr := deploy("proxy", proxy, beaconAddr, initData)

	fmt.Println("\n[2/4] beacon owner")
	if *beaconOwner != "" && common.HexToAddress(*beaconOwner) != deployer {
		if err := reg.Send(ctx, c, auth, beacon.ABI, beaconAddr, "transferOwnership", common.HexToAddress(*beaconOwner)); err != nil {
			reg.Fatalf("%v", err)
		}
	} else {
		fmt.Println("  kept by the deploy key")
	}

	fmt.Println("\n[3/4] registry admin")
	if *admin != "" && common.HexToAddress(*admin) != deployer {
		if err := reg.Send(ctx, c, auth, impl.ABI, proxyAddr, "transferAdmin", common.HexToAddress(*admin)); err != nil {
			reg.Fatalf("%v", err)
		}
	} else {
		fmt.Println("  kept by the deploy key")
	}

	// Read back rather than trust the transactions: this is what is in force.
	fmt.Println("\n[4/4] read back")
	ownerNow, err := reg.Call(ctx, c, beacon.ABI, beaconAddr, common.Address{}, "owner")
	if err != nil {
		reg.Fatalf("beacon.owner(): %v", err)
	}
	adminNow, err := reg.Call(ctx, c, impl.ABI, proxyAddr, common.Address{}, "admin")
	if err != nil {
		reg.Fatalf("admin(): %v", err)
	}
	version, err := reg.Call(ctx, c, impl.ABI, proxyAddr, common.Address{}, "version")
	if err != nil {
		reg.Fatalf("version(): %v", err)
	}

	fmt.Printf(`
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
DEPLOYED on %s — record these in CONTRACTS.md
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Proxy (users call this) : %s
Beacon                  : %s
Implementation          : %s   (version %v)
Beacon owner (upgrades) : %s
Registry admin          : %s
minStakeAmount          : %s wei
lockPeriod              : %d s

%s/address/%s
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
`, n.Name, proxyAddr.Hex(), beaconAddr.Hex(), implAddr.Hex(), version[0],
		ownerNow[0].(common.Address).Hex(), adminNow[0].(common.Address).Hex(),
		minStake, *lock, n.Explorer, proxyAddr.Hex())

	if !*verify {
		fmt.Printf("Next: go run ./cmd/verify/ --network %s --proxy %s\n", n.Name, proxyAddr.Hex())
		return
	}
	// A failed verification leaves the deployment exactly as it is; it can be
	// retried with cmd/verify, so it is reported rather than treated as fatal.
	fmt.Println("\nVerifying on the explorer...")
	if explorer.New(n, c).All(ctx, explorer.Implementation(implAddr), explorer.Beacon(beaconAddr), explorer.Proxy(proxyAddr)) > 0 {
		fmt.Printf("Retry: go run ./cmd/verify/ --network %s --proxy %s\n", n.Name, proxyAddr.Hex())
		os.Exit(1)
	}
}
