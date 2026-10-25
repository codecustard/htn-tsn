// hoosat-verify runs a signed transaction from the prototype through HTND's own consensus code:
// HTND decodes the output addresses, computes the sighash, and executes every input script.
// It shares no code with the Rust prototype, so a pass means the FROST signature is valid on Hoosat.
//
// 64-bit values are decimal strings in the JSON (see chain::u64_string).
//
// Usage: go run . <signed-tx.json>
package main

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"

	"github.com/HoosatNetwork/HTND/v2/domain/consensus/model/externalapi"
	"github.com/HoosatNetwork/HTND/v2/domain/consensus/utils/consensushashing"
	"github.com/HoosatNetwork/HTND/v2/domain/consensus/utils/subnetworks"
	"github.com/HoosatNetwork/HTND/v2/domain/consensus/utils/txscript"
	"github.com/HoosatNetwork/HTND/v2/domain/consensus/utils/utxo"
	"github.com/HoosatNetwork/HTND/v2/util"
)

type txInput struct {
	PrevTxid        string `json:"prev_txid"`
	Index           uint32 `json:"index"`
	Amount          uint64 `json:"amount,string"`
	ScriptPubkey    string `json:"script_pubkey"`
	Sequence        uint64 `json:"sequence,string"`
	SigOpCount      uint8  `json:"sig_op_count"`
	SignatureScript string `json:"signature_script"`
}

type txOutput struct {
	Address string `json:"address"`
	Amount  uint64 `json:"amount,string"`
}

type signedTx struct {
	Network  string     `json:"network"`
	Inputs   []txInput  `json:"inputs"`
	Outputs  []txOutput `json:"outputs"`
	LockTime uint64     `json:"lock_time,string"`
}

func must(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func mustHex(s string) []byte {
	b, err := hex.DecodeString(s)
	must(err)
	return b
}

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "usage: hoosat-verify <signed-tx.json>")
		os.Exit(2)
	}
	raw, err := os.ReadFile(os.Args[1])
	must(err)
	var stx signedTx
	must(json.Unmarshal(raw, &stx))

	prefix := map[string]util.Bech32Prefix{
		"hoosat-mainnet": util.Bech32PrefixHoosat,
		"hoosat-testnet": util.Bech32PrefixHoosatTest,
	}[stx.Network]
	if prefix == util.Bech32PrefixUnknown {
		must(fmt.Errorf("not a Hoosat transaction: %s", stx.Network))
	}

	tx := &externalapi.DomainTransaction{Version: 0, LockTime: stx.LockTime, SubnetworkID: subnetworks.SubnetworkIDNative}
	for _, in := range stx.Inputs {
		id, err := externalapi.NewDomainTransactionIDFromByteSlice(mustHex(in.PrevTxid))
		must(err)
		spk := &externalapi.ScriptPublicKey{Script: mustHex(in.ScriptPubkey), Version: 0}
		tx.Inputs = append(tx.Inputs, &externalapi.DomainTransactionInput{
			PreviousOutpoint: externalapi.DomainOutpoint{TransactionID: *id, Index: in.Index},
			SignatureScript:  mustHex(in.SignatureScript),
			Sequence:         in.Sequence,
			SigOpCount:       in.SigOpCount,
			UTXOEntry:        utxo.NewUTXOEntry(in.Amount, spk, false, 0),
		})
	}
	for _, out := range stx.Outputs {
		addr, err := util.DecodeAddress(out.Address, prefix) // HTND's own address decoder
		must(err)
		spk, err := txscript.PayToAddrScript(addr)
		must(err)
		tx.Outputs = append(tx.Outputs, &externalapi.DomainTransactionOutput{Value: out.Amount, ScriptPublicKey: spk})
	}

	reused := &consensushashing.SighashReusedValues{}
	for i, in := range tx.Inputs {
		vm, err := txscript.NewEngine(in.UTXOEntry.ScriptPublicKey(), tx, i, txscript.ScriptNoFlags,
			txscript.NewSigCache(100), txscript.NewSigCacheECDSA(100), txscript.NewMLDSA44Cache(100, 100), reused)
		must(err)
		if err := vm.Execute(); err != nil {
			must(fmt.Errorf("HTND script engine rejected input %d: %w", i, err))
		}
	}
	fmt.Printf("HTND v2 consensus engine: all %d input(s) valid\n", len(tx.Inputs))
}
