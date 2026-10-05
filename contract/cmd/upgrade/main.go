// cmd/upgrade — upgrades TappRegistry: puts the new implementation on chain and
// gets the beacon pointed at it, by whatever owns the beacon.
//
// Run `forge build` in contract/ first. Usage:
//
//	PRIVATE_KEY=0x<throwaway> go run ./cmd/upgrade/ --network testnet
//	go run ./cmd/upgrade/ --network testnet --check 0x<new implementation>
//
// Deploying an implementation needs no authority, so the key here only pays gas.
// The switch (beacon.upgradeTo) is the owner's, and what happens depends on what
// the owner is — read from the chain, not configured:
//
//	owner == this key     the switch is sent here (dev chains)
//	owner is a wallet     the exact transaction is printed for the owner to
//	                      sign elsewhere — after simulating it AS the owner
//	owner is a contract   treated as an OpenZeppelin TimelockController: the
//	                      schedule and execute transactions are printed, with
//	                      the delay read from it
//
// Before anything changes, the registry's state is snapshotted; --check confirms
// the switch landed and the snapshot is unchanged (or, for a timelock, where the
// operation stands).
package main

import (
	"context"
	"flag"
	"fmt"
	"math/big"
	"os"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethclient"

	reg "github.com/0gfoundation/0g-tapp/contract/cmd/internal/registry"
)

// The parts of OpenZeppelin's TimelockController this needs.
const timelockABI = `[
 {"type":"function","name":"getMinDelay","stateMutability":"view","inputs":[],"outputs":[{"type":"uint256"}]},
 {"type":"function","name":"hashOperation","stateMutability":"pure","inputs":[{"name":"target","type":"address"},{"name":"value","type":"uint256"},{"name":"data","type":"bytes"},{"name":"predecessor","type":"bytes32"},{"name":"salt","type":"bytes32"}],"outputs":[{"type":"bytes32"}]},
 {"type":"function","name":"getTimestamp","stateMutability":"view","inputs":[{"name":"id","type":"bytes32"}],"outputs":[{"type":"uint256"}]},
 {"type":"function","name":"hasRole","stateMutability":"view","inputs":[{"name":"role","type":"bytes32"},{"name":"account","type":"address"}],"outputs":[{"type":"bool"}]},
 {"type":"function","name":"schedule","stateMutability":"nonpayable","inputs":[{"name":"target","type":"address"},{"name":"value","type":"uint256"},{"name":"data","type":"bytes"},{"name":"predecessor","type":"bytes32"},{"name":"salt","type":"bytes32"},{"name":"delay","type":"uint256"}],"outputs":[]},
 {"type":"function","name":"execute","stateMutability":"payable","inputs":[{"name":"target","type":"address"},{"name":"value","type":"uint256"},{"name":"payload","type":"bytes"},{"name":"predecessor","type":"bytes32"},{"name":"salt","type":"bytes32"}],"outputs":[]}
]`

var proposerRole = crypto.Keccak256Hash([]byte("PROPOSER_ROLE"))

type ctxT struct {
	ctx      context.Context
	c        *ethclient.Client
	n        reg.Network
	registry reg.Artifact
	beacon   reg.Artifact
	tl       abi.ABI
	proxy    common.Address
	beaconAt common.Address
	apps     []string
	state    string
}

func main() {
	fs := flag.NewFlagSet("upgrade", flag.ExitOnError)
	netFlags := reg.RegisterNetworkFlags(fs)
	keyFlags := reg.RegisterKeyFlags(fs)
	proxyHex := fs.String("proxy", "", "the registry proxy (default: the network's, from CONTRACTS.md)")
	implHex := fs.String("impl", "", "an implementation already deployed: skip the deploy, print the switch")
	check := fs.String("check", "", "after the switch: confirm the beacon points at this implementation and the state is unchanged")
	appsFlag := fs.String("apps", "0g-kms", "comma-separated app ids whose records are snapshotted")
	stateFile := fs.String("state-file", "", "snapshot file (default upgrade-state.<proxy>.txt)")
	proposer := fs.String("proposer", "", "timelock only: an address holding PROPOSER_ROLE, to simulate the schedule call as")
	_ = fs.Parse(os.Args[1:])

	n, err := netFlags.Resolve()
	if err != nil {
		reg.Fatalf("%v", err)
	}
	if *proxyHex == "" {
		*proxyHex = n.Proxy
	}
	ctx, cancel := reg.Ctx()
	defer cancel()
	c, err := reg.Dial(ctx, n)
	if err != nil {
		reg.Fatalf("%v", err)
	}
	t := &ctxT{ctx: ctx, c: c, n: n, proxy: common.HexToAddress(*proxyHex)}
	if t.registry, err = reg.LoadArtifact("TappRegistry.sol", "TappRegistry"); err != nil {
		reg.Fatalf("%v", err)
	}
	if t.beacon, err = reg.LoadArtifact("UpgradeableBeacon.sol", "UpgradeableBeacon"); err != nil {
		reg.Fatalf("%v", err)
	}
	t.tl, _ = abi.JSON(strings.NewReader(timelockABI))
	if t.beaconAt, err = reg.BeaconOf(ctx, c, t.proxy); err != nil {
		reg.Fatalf("%v", err)
	}
	for _, a := range strings.Split(*appsFlag, ",") {
		if a = strings.TrimSpace(a); a != "" {
			t.apps = append(t.apps, a)
		}
	}
	t.state = *stateFile
	if t.state == "" {
		t.state = "upgrade-state." + t.proxy.Hex() + ".txt"
	}

	owner := t.addr(t.beacon.ABI, t.beaconAt, "owner")
	current := t.addr(t.beacon.ABI, t.beaconAt, "implementation")
	fmt.Printf("Network        : %s (chain %d)\nRegistry proxy : %s\nBeacon         : %s (read from the proxy)\n",
		n.Name, n.ChainID, t.proxy.Hex(), t.beaconAt.Hex())
	fmt.Printf("Beacon owner   : %s\nImplementation : %s (version %s)\n", owner.Hex(), current.Hex(), t.version(t.proxy))

	if *check != "" {
		t.check(common.HexToAddress(*check), owner)
		return
	}

	// Snapshot BEFORE anything changes, and never over an existing one: a second
	// run must not quietly replace the baseline the first one recorded.
	if _, err := os.Stat(t.state); err == nil {
		reg.Fatalf("%s exists — it is the baseline of an upgrade in progress. Finish it with --check, or remove the file to start over", t.state)
	}
	if err := os.WriteFile(t.state, []byte(strings.Join(t.snapshot(), "\n")+"\n"), 0o644); err != nil {
		reg.Fatalf("write %s: %v", t.state, err)
	}
	fmt.Printf("State snapshot : %s\n", t.state)

	var impl common.Address
	var auth *bind.TransactOpts
	var me common.Address
	if *implHex != "" {
		impl = common.HexToAddress(*implHex)
	} else {
		key, err := keyFlags.Load()
		if err != nil {
			reg.Fatalf("%v", err)
		}
		me = reg.Address(key)
		if auth, err = reg.Transactor(ctx, c, key, n.ChainID); err != nil {
			reg.Fatalf("%v", err)
		}
		fmt.Printf("\n[1/2] deploy implementation (paid by %s)\n", me.Hex())
		addr, tx, _, err := bind.DeployContract(auth, t.registry.ABI, t.registry.Bytecode, c)
		if err != nil {
			reg.Fatalf("deploy: %v", err)
		}
		if _, err := reg.Mined(ctx, c, tx, "deploy implementation"); err != nil {
			reg.Fatalf("%v", err)
		}
		impl = addr
	}
	if isC, _ := reg.IsContract(ctx, c, impl); !isC {
		reg.Fatalf("no code at %s", impl.Hex())
	}
	fmt.Printf("  new implementation %s (version %s)\n", impl.Hex(), t.version(impl))

	upgradeData, _ := t.beacon.ABI.Pack("upgradeTo", impl)
	// The inner call, as the owner, must succeed — or there is nothing to sign.
	if _, err := reg.Call(ctx, c, t.beacon.ABI, t.beaconAt, owner, "upgradeTo", impl); err != nil {
		reg.Fatalf("upgradeTo(%s) reverts when sent by the beacon owner %s: %v", impl.Hex(), owner.Hex(), err)
	}

	fmt.Println("\n[2/2] switch the beacon")
	ownerIsContract, err := reg.IsContract(ctx, c, owner)
	if err != nil {
		reg.Fatalf("%v", err)
	}
	switch {
	case owner == me:
		if err := reg.Send(ctx, c, auth, t.beacon.ABI, t.beaconAt, "upgradeTo", impl); err != nil {
			reg.Fatalf("%v", err)
		}
		t.check(impl, owner)
	case !ownerIsContract:
		fmt.Printf("  Simulated as the owner: succeeds. Send this FROM %s:\n\n", owner.Hex())
		printTx(t.beaconAt, upgradeData, n.ChainID)
		fmt.Println("  (MetaMask: Settings → Advanced → Show hex data; priority fee ≥ 2 gwei.)")
		fmt.Printf("\nThen: go run ./cmd/upgrade/ --network %s --check %s\n", n.Name, impl.Hex())
	default:
		t.timelock(owner, impl, upgradeData, *proposer)
	}
}

// timelock prints the two transactions an OpenZeppelin TimelockController needs.
func (t *ctxT) timelock(tl, impl common.Address, upgradeData []byte, proposer string) {
	out, err := reg.Call(t.ctx, t.c, t.tl, tl, common.Address{}, "getMinDelay")
	if err != nil {
		reg.Fatalf("the beacon owner %s is a contract but not a TimelockController (getMinDelay: %v) — route the upgradeTo call through it by hand", tl.Hex(), err)
	}
	delay := out[0].(*big.Int)
	salt := saltFor(impl)
	var zero [32]byte
	schedule, _ := t.tl.Pack("schedule", t.beaconAt, big.NewInt(0), upgradeData, zero, salt, delay)
	execute, _ := t.tl.Pack("execute", t.beaconAt, big.NewInt(0), upgradeData, zero, salt)

	if proposer != "" {
		p := common.HexToAddress(proposer)
		r, err := reg.Call(t.ctx, t.c, t.tl, tl, common.Address{}, "hasRole", proposerRole, p)
		if err != nil || !r[0].(bool) {
			reg.Fatalf("%s does not hold PROPOSER_ROLE on %s", p.Hex(), tl.Hex())
		}
		if _, err := t.c.CallContract(t.ctx, callMsg(p, tl, schedule), nil); err != nil {
			reg.Fatalf("schedule reverts when sent by %s: %v", p.Hex(), err)
		}
		fmt.Printf("  Simulated schedule as proposer %s: succeeds.\n", p.Hex())
	} else {
		fmt.Println("  (pass --proposer <address> to simulate the schedule call as that proposer)")
	}

	fmt.Printf("  The beacon owner is a timelock (%s), delay %s.\n\n", tl.Hex(), time.Duration(delay.Int64())*time.Second)
	fmt.Println("  Step 1 — schedule, from a PROPOSER:")
	printTx(tl, schedule, t.n.ChainID)
	fmt.Printf("  Step 2 — execute, from an EXECUTOR, no earlier than %s after step 1 lands:\n", time.Duration(delay.Int64())*time.Second)
	printTx(tl, execute, t.n.ChainID)
	fmt.Printf("  Operation id %s — --check reports where it stands.\n", t.opID(tl, impl, upgradeData).Hex())
	fmt.Printf("\nThen: go run ./cmd/upgrade/ --network %s --check %s\n", t.n.Name, impl.Hex())
}

// check: did the switch land, and is everything else as it was?
func (t *ctxT) check(impl, owner common.Address) {
	now := t.addr(t.beacon.ABI, t.beaconAt, "implementation")
	if now != impl {
		fmt.Printf("\n✗ the beacon still points at %s — the upgrade has not landed\n", now.Hex())
		if isC, _ := reg.IsContract(t.ctx, t.c, owner); isC {
			upgradeData, _ := t.beacon.ABI.Pack("upgradeTo", impl)
			id := t.opID(owner, impl, upgradeData)
			if out, err := reg.Call(t.ctx, t.c, t.tl, owner, common.Address{}, "getTimestamp", id); err == nil {
				switch ts := out[0].(*big.Int); {
				case ts.Sign() == 0:
					fmt.Println("  timelock: not scheduled")
				case ts.Cmp(big.NewInt(1)) == 0:
					fmt.Println("  timelock: executed (yet the beacon moved elsewhere since)")
				default:
					at := time.Unix(ts.Int64(), 0)
					if time.Now().Before(at) {
						fmt.Printf("  timelock: scheduled, executable from %s (in %s)\n", at.Format(time.RFC3339), time.Until(at).Round(time.Minute))
					} else {
						fmt.Printf("  timelock: ready since %s — send the execute transaction\n", at.Format(time.RFC3339))
					}
				}
			}
		}
		os.Exit(1)
	}
	fmt.Printf("\n✓ beacon → %s, version %s\n", impl.Hex(), t.version(t.proxy))

	raw, err := os.ReadFile(t.state)
	if err != nil {
		fmt.Printf("(no snapshot at %s — state not compared)\n", t.state)
		return
	}
	before := strings.Split(strings.TrimSpace(string(raw)), "\n")
	after := t.snapshot()
	var diff []string
	for i := range before {
		if i >= len(after) || before[i] != after[i] {
			diff = append(diff, "  before: "+before[i])
			if i < len(after) {
				diff = append(diff, "  after:  "+after[i])
			}
		}
	}
	if len(diff) > 0 {
		fmt.Printf("✗ state differs from %s:\n%s\n", t.state, strings.Join(diff, "\n"))
		os.Exit(1)
	}
	fmt.Printf("✓ state unchanged across the upgrade (%d values from %s)\n", len(before), t.state)
}

// snapshot: every value an upgrade must not change.
func (t *ctxT) snapshot() []string {
	var lines []string
	add := func(label, method string, args ...any) {
		out, err := reg.Call(t.ctx, t.c, t.registry.ABI, t.proxy, common.Address{}, method, args...)
		if err != nil {
			reg.Fatalf("snapshot %s: %v", label, err)
		}
		lines = append(lines, fmt.Sprintf("%s %v", label, out))
	}
	add("admin", "admin")
	add("minStakeAmount", "minStakeAmount")
	add("lockPeriod", "lockPeriod")
	for _, a := range t.apps {
		add("app["+a+"]", "getAppInfo", a)
		add("nodes["+a+"]", "getNodeList", a)
		add("ack["+a+"]", "getAckVersion", a)
	}
	return lines
}

func (t *ctxT) addr(a abi.ABI, at common.Address, method string) common.Address {
	out, err := reg.Call(t.ctx, t.c, a, at, common.Address{}, method)
	if err != nil {
		reg.Fatalf("%s(): %v", method, err)
	}
	return out[0].(common.Address)
}

func (t *ctxT) version(at common.Address) string {
	out, err := reg.Call(t.ctx, t.c, t.registry.ABI, at, common.Address{}, "version")
	if err != nil {
		return "?"
	}
	return fmt.Sprintf("%q", out[0])
}

func (t *ctxT) opID(tl, impl common.Address, upgradeData []byte) common.Hash {
	var zero [32]byte
	out, err := reg.Call(t.ctx, t.c, t.tl, tl, common.Address{}, "hashOperation", t.beaconAt, big.NewInt(0), upgradeData, zero, saltFor(impl))
	if err != nil {
		return common.Hash{}
	}
	return common.Hash(out[0].([32]byte))
}

// saltFor is deterministic per implementation, so --check can find the
// operation again without being told the salt.
func saltFor(impl common.Address) [32]byte {
	return crypto.Keccak256Hash([]byte("TappRegistry.upgradeTo:" + strings.ToLower(impl.Hex())))
}

func printTx(to common.Address, data []byte, chainID int64) {
	fmt.Printf("    to:    %s\n    value: 0\n    data:  0x%x\n    chain: %d\n\n", to.Hex(), data, chainID)
}

func callMsg(from, to common.Address, data []byte) ethereum.CallMsg {
	return ethereum.CallMsg{From: from, To: &to, Data: data}
}
