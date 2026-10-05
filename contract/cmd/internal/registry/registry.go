// Package registry is what the deploy / upgrade / verify tools share: which
// network they talk to, how they get a signing key, and how they reach the
// compiled contracts.
//
// It reads forge's build output (out/) directly, so the tools need nothing
// beyond `forge build` — no generated bindings.
package registry

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"math/big"
	"os"
	"strings"
	"time"

	"crypto/ecdsa"
	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/accounts/keystore"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethclient"
	"golang.org/x/term"
)

// ─── Networks ────────────────────────────────────────────────────────────────

// Network is everything that differs between the 0G networks.
type Network struct {
	Name        string
	RPC         string
	ChainID     int64
	ExplorerAPI string // Etherscan-compatible
	Explorer    string // for links
	Proxy       string // the TappRegistry users call (CONTRACTS.md)
	// Mainnet authority must never stay with a deploy key: see Deploy.
	RequireAuthorityHandoff bool
}

var Networks = map[string]Network{
	"testnet": {
		Name:        "testnet",
		RPC:         "https://evmrpc-testnet.0g.ai",
		ChainID:     16602,
		ExplorerAPI: "https://chainscan-galileo.0g.ai/open/api",
		Explorer:    "https://chainscan-galileo.0g.ai",
		Proxy:       "0x2Ce80374318B1d7Fb3345724457a182E0ad165c9",
	},
	"mainnet": {
		Name:                    "mainnet",
		RPC:                     "https://evmrpc.0g.ai",
		ChainID:                 16661,
		ExplorerAPI:             "https://chainscan.0g.ai/open/api",
		Explorer:                "https://chainscan.0g.ai",
		Proxy:                   "0x54874F536301c993922Dd95097e3902e7FBfe612",
		RequireAuthorityHandoff: true,
	},
}

// NetworkFlags registers --network plus per-field overrides. Overrides exist for
// a local fork or a dev chain; the presets are what the networks actually are.
type NetworkFlags struct {
	name, rpc, explorerAPI, explorer string
	chainID                          int64
}

func RegisterNetworkFlags(fs *flag.FlagSet) *NetworkFlags {
	f := &NetworkFlags{}
	fs.StringVar(&f.name, "network", "", "testnet | mainnet (required)")
	fs.StringVar(&f.rpc, "rpc", "", "override the network's RPC (e.g. a local anvil fork)")
	fs.Int64Var(&f.chainID, "chain-id", 0, "override the network's chain id")
	fs.StringVar(&f.explorerAPI, "api", "", "override the explorer API URL")
	fs.StringVar(&f.explorer, "explorer", "", "override the explorer URL (links only)")
	return f
}

func (f *NetworkFlags) Resolve() (Network, error) {
	n, ok := Networks[f.name]
	if !ok {
		return Network{}, fmt.Errorf("--network must be testnet or mainnet, got %q", f.name)
	}
	if f.rpc != "" {
		n.RPC = f.rpc
	}
	if f.chainID != 0 {
		n.ChainID = f.chainID
	}
	if f.explorerAPI != "" {
		n.ExplorerAPI = f.explorerAPI
	}
	if f.explorer != "" {
		n.Explorer = f.explorer
	}
	return n, nil
}

// Dial connects and refuses an RPC that is not on the chain the network says —
// the cheapest way to stop a mainnet command landing on testnet, or vice versa.
func Dial(ctx context.Context, n Network) (*ethclient.Client, error) {
	c, err := ethclient.DialContext(ctx, n.RPC)
	if err != nil {
		return nil, fmt.Errorf("dial %s: %w", n.RPC, err)
	}
	id, err := c.ChainID(ctx)
	if err != nil {
		return nil, fmt.Errorf("chain id: %w", err)
	}
	if id.Int64() != n.ChainID {
		return nil, fmt.Errorf("%s is chain %d, but --network %s is chain %d", n.RPC, id, n.Name, n.ChainID)
	}
	return c, nil
}

// ─── Signing key ─────────────────────────────────────────────────────────────

// KeyFlags: a foundry/geth keystore (preferred), or PRIVATE_KEY in the
// environment. --key still works for throwaway keys, with a warning: a key on
// the command line is in the shell history and the process list.
type KeyFlags struct {
	keystore, passwordFile, key string
}

func RegisterKeyFlags(fs *flag.FlagSet) *KeyFlags {
	k := &KeyFlags{}
	fs.StringVar(&k.keystore, "keystore", "", "keystore file (e.g. ~/.foundry/keystores/<name>); password prompted")
	fs.StringVar(&k.passwordFile, "password-file", "", "read the keystore password from this file instead of prompting")
	fs.StringVar(&k.key, "key", "", "raw private key — throwaway keys only (visible in the process list); prefer --keystore or PRIVATE_KEY")
	return k
}

func (k *KeyFlags) Load() (*ecdsa.PrivateKey, error) {
	switch {
	case k.keystore != "":
		raw, err := os.ReadFile(k.keystore)
		if err != nil {
			return nil, err
		}
		pw, err := k.password()
		if err != nil {
			return nil, err
		}
		key, err := keystore.DecryptKey(raw, pw)
		if err != nil {
			return nil, fmt.Errorf("decrypt keystore: %w", err)
		}
		return key.PrivateKey, nil
	case os.Getenv("PRIVATE_KEY") != "":
		return parseKey(os.Getenv("PRIVATE_KEY"))
	case k.key != "":
		fmt.Fprintln(os.Stderr, "warning: --key puts the private key in the process list and shell history; use it for throwaway keys only")
		return parseKey(k.key)
	}
	return nil, errors.New("no signing key: pass --keystore <file>, or set PRIVATE_KEY")
}

func (k *KeyFlags) password() (string, error) {
	if k.passwordFile != "" {
		b, err := os.ReadFile(k.passwordFile)
		return strings.TrimRight(string(b), "\r\n"), err
	}
	fmt.Fprint(os.Stderr, "keystore password: ")
	b, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Fprintln(os.Stderr)
	return string(b), err
}

func parseKey(s string) (*ecdsa.PrivateKey, error) {
	return crypto.HexToECDSA(strings.TrimPrefix(strings.TrimSpace(s), "0x"))
}

func Address(k *ecdsa.PrivateKey) common.Address { return crypto.PubkeyToAddress(k.PublicKey) }

// ─── Artifacts ───────────────────────────────────────────────────────────────

type Artifact struct {
	ABI      abi.ABI
	Bytecode []byte
}

// LoadArtifact reads out/<file>/<name>.json, which `forge build` writes.
func LoadArtifact(file, name string) (Artifact, error) {
	path := fmt.Sprintf("out/%s/%s.json", file, name)
	raw, err := os.ReadFile(path)
	if err != nil {
		return Artifact{}, fmt.Errorf("read %s (run `forge build` in contract/ first): %w", path, err)
	}
	var a struct {
		ABI      json.RawMessage `json:"abi"`
		Bytecode struct {
			Object string `json:"object"`
		} `json:"bytecode"`
	}
	if err := json.Unmarshal(raw, &a); err != nil {
		return Artifact{}, fmt.Errorf("parse %s: %w", path, err)
	}
	parsed, err := abi.JSON(strings.NewReader(string(a.ABI)))
	if err != nil {
		return Artifact{}, fmt.Errorf("abi in %s: %w", path, err)
	}
	code, err := hex.DecodeString(strings.TrimPrefix(a.Bytecode.Object, "0x"))
	if err != nil {
		return Artifact{}, fmt.Errorf("bytecode in %s: %w", path, err)
	}
	return Artifact{ABI: parsed, Bytecode: code}, nil
}

// ─── Chain I/O ───────────────────────────────────────────────────────────────

// BeaconSlot is the ERC-1967 storage slot holding a BeaconProxy's beacon.
var BeaconSlot = common.HexToHash("0xa3f0ad74e5423aebfd80d3ef4346578335a9a72aeaee59ff6cb3582b35133d50")

// BeaconOf reads a proxy's beacon from its storage — never typed by hand, so a
// command cannot be pointed at the wrong beacon.
func BeaconOf(ctx context.Context, c *ethclient.Client, proxy common.Address) (common.Address, error) {
	raw, err := c.StorageAt(ctx, proxy, BeaconSlot, nil)
	if err != nil {
		return common.Address{}, fmt.Errorf("read beacon slot: %w", err)
	}
	b := common.BytesToAddress(raw)
	if b == (common.Address{}) {
		return b, fmt.Errorf("%s has no beacon — is it a BeaconProxy?", proxy.Hex())
	}
	return b, nil
}

// MinGasPrice: 0G refuses a priority fee under 2 gwei, which some RPCs'
// suggestions undercut. Transactions are sent legacy at max(suggested, this).
var MinGasPrice = big.NewInt(3_000_000_000)

func Transactor(ctx context.Context, c *ethclient.Client, k *ecdsa.PrivateKey, chainID int64) (*bind.TransactOpts, error) {
	auth, err := bind.NewKeyedTransactorWithChainID(k, big.NewInt(chainID))
	if err != nil {
		return nil, err
	}
	gp, err := c.SuggestGasPrice(ctx)
	if err != nil || gp.Cmp(MinGasPrice) < 0 {
		gp = new(big.Int).Set(MinGasPrice)
	}
	auth.GasPrice = gp
	auth.Context = ctx
	return auth, nil
}

// Mined waits for tx and fails on a revert.
func Mined(ctx context.Context, c *ethclient.Client, tx *types.Transaction, what string) (*types.Receipt, error) {
	fmt.Printf("  %s tx %s\n", what, tx.Hash().Hex())
	r, err := bind.WaitMined(ctx, c, tx)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", what, err)
	}
	if r.Status != types.ReceiptStatusSuccessful {
		return nil, fmt.Errorf("%s: transaction reverted", what)
	}
	return r, nil
}

// Call packs method on a, eth_calls it at `to` (optionally AS `from`), unpacks.
func Call(ctx context.Context, c *ethclient.Client, a abi.ABI, to, from common.Address, method string, args ...any) ([]any, error) {
	data, err := a.Pack(method, args...)
	if err != nil {
		return nil, err
	}
	out, err := c.CallContract(ctx, ethereum.CallMsg{From: from, To: &to, Data: data}, nil)
	if err != nil {
		return nil, err
	}
	return a.Unpack(method, out)
}

// Send packs and sends method on a at `to`, and waits for it.
func Send(ctx context.Context, c *ethclient.Client, auth *bind.TransactOpts, a abi.ABI, to common.Address, method string, args ...any) error {
	tx, err := bind.NewBoundContract(to, a, c, c, c).Transact(auth, method, args...)
	if err != nil {
		return fmt.Errorf("%s: %w", method, err)
	}
	_, err = Mined(ctx, c, tx, method)
	return err
}

// IsContract: whether code lives at addr (a timelock or multisig, vs a wallet).
func IsContract(ctx context.Context, c *ethclient.Client, addr common.Address) (bool, error) {
	code, err := c.CodeAt(ctx, addr, nil)
	return len(code) > 0, err
}

// Ctx is a context with the timeout every tool uses.
func Ctx() (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), 10*time.Minute)
}

func Fatalf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "error: "+format+"\n", args...)
	os.Exit(1)
}
