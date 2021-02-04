package main

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"math/big"
	"os/exec"
	"strconv"
	"strings"

	"github.com/JFJun/go-substrate-crypto/ss58"
	gsrpc "github.com/centrifuge/go-substrate-rpc-client/v2"
	"github.com/centrifuge/go-substrate-rpc-client/v2/config"
	"github.com/centrifuge/go-substrate-rpc-client/v2/scale"
	"github.com/centrifuge/go-substrate-rpc-client/v2/signature"
	"github.com/centrifuge/go-substrate-rpc-client/v2/types"
	"github.com/minio/blake2b-simd"
	"github.com/vedhavyas/go-subkey"

	// gsrpc "github.com/centrifuge/go-substrate-rpc-client"
	// "github.com/centrifuge/go-substrate-rpc-client/config"
	// "github.com/centrifuge/go-substrate-rpc-client/scale"
	// "github.com/centrifuge/go-substrate-rpc-client/signature"
	// "github.com/centrifuge/go-substrate-rpc-client/types"

	iScale "github.com/itering/scale.go"
	iTypes "github.com/itering/scale.go/types"
	iUtil "github.com/itering/subscan/util"
	iSS58 "github.com/itering/subscan/util/ss58"
	iMetadata "github.com/itering/substrate-api-rpc/metadata"
	iRPC "github.com/itering/substrate-api-rpc/rpc"
	iWspool "github.com/itering/substrate-api-rpc/websocket"
)

func main() {
	// Get Height
	// getHeight()

	// Get Account
	// WestEnd Account
	// pk := PubKey("0x68ea05199a3fa035087e42c1cda32654d7d5a6540feac4587a2de4f92434e903")
	// local testing
	// alicePK := PubKey("0xd43593c715fdd31c61141abd04a99fd6822c8558854ccde39a5684e7a56da27d")
	// GetAccount(pk)

	// Get Address from bytes
	// pkb := []byte{231, 243, 184, 176, 29, 241, 47, 222, 44, 169, 30, 235, 237, 245, 113, 144, 127, 22, 55, 214, 171, 227, 93, 235, 112, 78, 15, 138, 71, 98, 173, 50}
	// GetAddressFromBytes(pkb)

	// GetAddress(pk)
	// Read Block Using Centrifuge
	readBlockUsingCentrifuge()

	// read block using Itering
	// readBlockUsingItering()
	//Send Tokens from Sr25519 account to Ed25519
	// transferAliceSr25519ToAliceEd25519()

	// Send Tokens from Sr25519 account to Ecdsa
	// transferAliceSr25519ToAliceEcdsa()

	// Currently: Invalid Transaction returns
	// Send Tokens from Ecdsa to Sr25519
	// transferAliceEcdsaToBobSr25519()

	// TODO:
	// Send Tokens from Ecsda to Ed25519
	// transferAliceEcdsaToBobEd25519()

	// Send Tokens from Ed25519 to Shnorkell
	// transferAliceEd25519ToBobSr25519()

	// TODO:
	// Send Tokens from Ed25519 to Ecdsa
	// transferAliceEd25519ToBobEcdsa()
}

func GetAddressFromBytes(pkb []byte) error {
	fmt.Println("BXL: DOTChain pk bytes: ", pkb)
	fmt.Println("BXL: ss58.PolkadotPrefix: ", ss58.PolkadotPrefix)
	// GetAddress(poolPubKey common.PubKey) string
	// GetAccount(poolPubKey common.PubKey) (common.Account, error)
	polkadotAddress, err := ss58.Encode(pkb, ss58.PolkadotPrefix)
	if err != nil {
		fmt.Println("BXL: polkadotAddress error: ", err)
		return err
	}
	fmt.Println("BXL: polkadotAddress: ", polkadotAddress)
	return nil
}

func readBlockUsingItering() {
	SetWSConnection()
	blockHash := "0x39718cb67ed41fb088ecfa3b7e5fe775d6b4867b38f67bc5be291b36ede18d8b"

	codedMetadataAtHash, _ := iRPC.GetMetadataByHash(nil, blockHash)
	metadataInBytes := iUtil.HexToBytes(codedMetadataAtHash)
	m := iScale.MetadataDecoder{}
	m.Init(metadataInBytes)
	m.Process()

	iMetadata.Latest(&iMetadata.RuntimeRaw{
		Spec: 12,
		Raw:  strings.TrimPrefix(codedMetadataAtHash, "0x"),
	})

	currentMetadata := iMetadata.RuntimeMetadata[12]
	v := &iRPC.JsonRpcResult{}
	err := iWspool.SendWsRequest(nil, v, iRPC.ChainGetBlock(0, blockHash))
	if err != nil {
		fmt.Println("Could not read the block", err)
	}
	rpcBlock := v.ToBlock()

	blockHeight, err := strconv.ParseInt(hexaNumberToInteger(rpcBlock.Block.Header.Number), 16, 64)
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Println("BXL: readBlockUsingItering: blockHeight: ", blockHeight)

	decodedExtrinsics, _ := decodeExtrinsics(rpcBlock.Block.Extrinsics, currentMetadata, 12)

	for _, e := range decodedExtrinsics {
		_, err := parseExtrinsic(&e, blockHeight)
		if err != nil {
			fmt.Println(err)
		}
	}
}

// hexaNumberToInteger
func hexaNumberToInteger(hexaString string) string {
	// replace 0x or 0X with empty String
	numberStr := strings.Replace(hexaString, "0x", "", -1)
	numberStr = strings.Replace(numberStr, "0X", "", -1)
	return numberStr
}

// func GetAddress(poolPubKey PubKey) (string, error) {
// 	polkadotAddress, err := ss58.Encode(poolPubKey, ss58.PolkadotPrefix)
// 	if err != nil {
// 		return "", err
// 	}
// 	fmt.Printf("BXL: polkadotAddress: %v", polkadotAddress)

// address, err := NewAddress(polkadotAddress)
// if err != nil {
// 	return NoAddress, err
// }
// fmt.Printf("BXL: address: %v", address)

// 	return polkadotAddress, nil
// }

// PubKey String
type (
	PubKey string
)

type KeyringPair struct {
	// URI is the derivation path for the private key in subkey
	URI string
	// Address is an SS58 address
	Address string
	// PublicKey
	PublicKey []byte
}

func GetAccount(pk PubKey) {

	api, err := gsrpc.NewSubstrateAPI(config.Default().RPCURL)
	if err != nil {
		panic(err)
	}

	// types.SetSerDeOptions(types.SerDeOptions{NoPalletIndices: true})

	meta, err := api.RPC.State.GetMetadataLatest()
	if err != nil {
		panic(err)
	}

	var TestKeyringPairAlice = KeyringPair{
		URI:       "//Alice",
		PublicKey: []byte{0xd4, 0x35, 0x93, 0xc7, 0x15, 0xfd, 0xd3, 0x1c, 0x61, 0x14, 0x1a, 0xbd, 0x4, 0xa9, 0x9f, 0xd6, 0x82, 0x2c, 0x85, 0x58, 0x85, 0x4c, 0xcd, 0xe3, 0x9a, 0x56, 0x84, 0xe7, 0xa5, 0x6d, 0xa2, 0x7d}, //nolint:lll
		Address:   "5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKutQY",
	}
	fmt.Println("print test key ring", TestKeyringPairAlice.PublicKey)

	// Known account we want to use (available on dev chain, with funds)
	testAccount, err := types.HexDecodeString(string(pk))
	if err != nil {
		panic(err)
	}

	key, err := types.CreateStorageKey(meta, "System", "Account", testAccount, nil)
	if err != nil {
		panic(err)
	}

	// Retrieve the initial balance
	// var accountInfo types.AccountInfo
	// 16777216000000000000000000
	// 16777216000000000000000000

	var accountInfo AccountInfo
	ok, err := api.RPC.State.GetStorageLatest(key, &accountInfo)
	if err != nil || !ok {
		panic(err)
	}

	fmt.Printf("%#x has a balance of %v\n", testAccount, accountInfo.Data.Free.String())
	fmt.Printf("You may leave this example running and transfer any value to %#x\n", testAccount)
}

// AccountInfo data}
type AccountInfo struct {
	Nonce    types.U32
	Refcount types.U32
	Data     struct {
		Free       types.U128
		Reserved   types.U128
		MiscFrozen types.U128
		FreeFrozen types.U128
	}
}

// UtilityBatchCall Utility Batch Call
type UtilityBatchCall struct {
	CallIndex    string                  `json:"call_index"`
	CallFunction string                  `json:"call_function"`
	CallModule   string                  `json:"call_module"`
	CallArgs     []iTypes.ExtrinsicParam `json:"call_args"`
}

// TxInItem Transaction Item
type TxInItem struct {
	BlockHeight int64  `json:"block_height"`
	Tx          string `json:"tx"`     // Block Hash
	Memo        string `json:"memo"`   // Remarks Text
	Sender      string `json:"sender"` // From Address
	To          string `json:"to"`     // To Address
	Coins       []Coin `json:"coins"`
	Gas         Coin   `json:"gas"` // Gas price
}

type TxIn struct {
	Count string `json:"count"`
	// Chain                common.Chain `json:"chain"`
	TxArray              []TxInItem `json:"txArray"`
	Filtered             bool       `json:"filtered"`
	MemPool              bool       `json:"mem_pool"`          // indicate whether this item is in the mempool or not
	SentUnFinalised      bool       `json:"sent_un_finalised"` // indicate whehter unfinalised tx had been sent to THORChain
	Finalised            bool       `json:"finalised"`
	ConfirmationRequired int64      `json:"confirmation_required"`
}

// DOTAsset DOT
var DOTAsset = Asset{Chain: "DOT", Symbol: "DOT", Ticker: "DOT"}

// Chain is an alias of string , represent a block chain
type Chain string

// Symbol represent an asset
type Symbol string

// Ticker represent an asset
type Ticker string

// Asset Struct
type Asset struct {
	Chain  Chain  `json:"chain"`
	Symbol Symbol `json:"symbol"`
	Ticker Ticker `json:"ticker"`
}

// Coin struct
type Coin struct {
	Asset  Asset    `json:"asset"`
	Amount *big.Int `json:"amount"`
}

func parseExtrinsic(e *iScale.ExtrinsicDecoder, blockHeight int64) (TxInItem, error) {
	noTxIn := TxInItem{}
	err := iParseUtilityBatch(e, blockHeight)
	if err != nil {
		return noTxIn, err
	}
	return noTxIn, nil
}

func iParseUtilityBatch(e *iScale.ExtrinsicDecoder, blockHeight int64) error {
	if e.CallModule.Name == "Utility" && e.Call.Name == "batch" {
		calls := &[]UtilityBatchCall{}
		err := unmarshalAny(calls, e.Params[0].Value)
		if err != nil {
			return fmt.Errorf("unable to decode utility batch calls: %v", e.Params[0].Value)
		}
		fromAddressStr := fmt.Sprintf("%v", e.Address)
		fromAddress := iSS58.Encode(fromAddressStr, iUtil.StringToInt("42"))
		dest := ""
		value := ""
		memo := ""

		for _, c := range *calls {
			for _, a := range c.CallArgs {
				switch a.Name {
				case "dest":
					dest = iSS58.Encode(a.Value.(string), iUtil.StringToInt("42"))
					break
				case "value":
					value = a.Value.(string)
					break
				case "_remark":
					decodedMemo, err := hex.DecodeString(a.Value.(string))
					if err != nil {
						return fmt.Errorf("BXL: iParseUtilityBatch: unable to decode remark: %v", a.Value.(string))
					}
					memo = string(decodedMemo)
					break
				}
			}
		}
		amount := new(big.Int)
		amount, ok := amount.SetString(value, 10)
		if !ok {
			return fmt.Errorf("BXL: iParseUtilityBatch: unable to set amount string")
		}
		txInItem := INewUtilityBatchData(blockHeight, "", memo, fromAddress, dest, amount)
		fmt.Println("BXL: iParseUtilityBatch: txInItem ", txInItem)
	}
	return nil
}

func unmarshalAny(r interface{}, raw interface{}) error {
	j, err := json.Marshal(raw)
	if err != nil {
		return err
	}
	return json.Unmarshal(j, &r)
}

func INewUtilityBatchData(BlockHeight int64, Tx string, Memo string, Sender string, To string, Amount *big.Int) *TxInItem {
	coin := Coin{DOTAsset, Amount}
	txInItem := &TxInItem{
		BlockHeight: BlockHeight,
		Tx:          Tx,
		Memo:        Memo,
		Sender:      Sender,
		To:          To,
	}
	txInItem.Coins = append(txInItem.Coins, coin)
	txInItem.Gas = coin // BXL TODO: Gas price
	return txInItem
}

func decodeExtrinsics(list []string, metadata *iMetadata.Instant, spec int) (r []iScale.ExtrinsicDecoder, err error) {
	defer func() {
		if fatal := recover(); fatal != nil {
			err = fmt.Errorf("Recovering from panic in DecodeExtrinsic: %v", fatal)
		}
	}()

	m := iTypes.MetadataStruct(*metadata)
	for _, extrinsicRaw := range list {
		e := iScale.ExtrinsicDecoder{}
		option := iTypes.ScaleDecoderOption{Metadata: &m, Spec: spec}
		e.Init(iTypes.ScaleBytes{Data: iUtil.HexToBytes(extrinsicRaw)}, &option)
		e.Process()

		r = append(r, e)
	}
	return r, nil
}

func SetWSConnection() {
	iWspool.SetEndpoint("wss://westend-rpc.polkadot.io")
}

// DispatchInfo
type DispatchInfo struct {
	// Weight of this transaction
	Weight float64 `json:"weight"`
	// Class of this transaction
	Class string `json:"class"`
	// PaysFee indicates whether this transaction pays fees
	PartialFee string `json:"partialFee"`
}

func readBlockUsingCentrifuge() error {
	txInbound := TxIn{
		// Chain:    common.DOTChain,
		Filtered: false,
		MemPool:  false,
	}
	api := NewSubstrateAPI()
	metadata := GetMetadataLatest(api)
	fmt.Println("BXL: metadata: ")

	types.SetSerDeOptions(types.SerDeOptions{NoPalletIndices: true})
	fmt.Println("BXL: SetSerDeOptions: ")

	/// 0x39718cb67ed41fb088ecfa3b7e5fe775d6b4867b38f67bc5be291b36ede18d8b
	blockHash, err := api.RPC.Chain.GetBlockHash(3443522)
	// local testing
	// blockHash, err := api.RPC.Chain.GetBlockHash(25)

	if err != nil {
		return err
	}

	fmt.Println("BXL: readBlockUsingCentrifuge: blockHash: ", blockHash.Hex())
	// Get the block
	block, err := api.RPC.Chain.GetBlock(blockHash)
	if err != nil {
		panic(err)
	}

	// fmt.Println("BXL: readBlockUsingCentrifuge: block: ", block)

	// Go through each Extrinsics
	for i, ext := range block.Block.Extrinsics {
		// Match to Batch Transaction
		// WEST-END Section Index
		if ext.Method.CallIndex.SectionIndex == 16 && ext.Method.CallIndex.MethodIndex == 0 {
			// Local Section Index
			// if ext.Method.CallIndex.SectionIndex == 26 && ext.Method.CallIndex.MethodIndex == 0 {
			fmt.Println("BXL:  Batch Transaction: ")

			// Get payment info
			resInter := DispatchInfo{}
			// var res interface{}
			err := api.Client.Call(&resInter, "payment_queryInfo", ext, blockHash.Hex())
			if err != nil {
				panic(err)
			}
			fmt.Println("BXL:  payment_queryInfo PartialFee: ", resInter.PartialFee)
			partialFee := new(big.Int)
			partialFee, ok := partialFee.SetString(resInter.PartialFee, 10)
			if !ok {
				return fmt.Errorf("BXL: failed: unable to set amount string")
			}

			txInItem := TxInItem{}

			fmt.Println("BXL:  Fee: ", partialFee)

			coin := Coin{DOTAsset, partialFee}

			txInItem.Gas = coin
			txInItem.BlockHeight = int64(block.Block.Header.Number)
			txInItem.Tx = blockHash.Hex()

			decoder := scale.NewDecoder(bytes.NewReader(ext.Method.Args))

			sender, _ := subkey.SS58Address(ext.Signature.Signer.AsAccountID[:], uint8(42))
			fmt.Println("BXL: sender: ", sender)
			txInItem.Sender = sender
			// determine number of calls
			n, err := decoder.DecodeUintCompact()
			if err != nil {
				return err
			}
			fmt.Println("BXL: FetchTxs: calls ", i, "------", n)
			for call := uint64(0); call < n.Uint64(); call++ {
				callIndex := types.CallIndex{}
				err = decoder.Decode(&callIndex)
				if err != nil {
					return err
				}
				// how is it determining the call Index?
				fmt.Println("BXL: FetchTxs: callIndex ", i, "------", callIndex)
				callFunction := findModule(metadata, callIndex)
				for _, callArg := range callFunction.Args {
					if callArg.Type == "<T::Lookup as StaticLookup>::Source" {
						var argValue = types.AccountID{}
						_ = decoder.Decode(&argValue)
						ss58, _ := subkey.SS58Address(argValue[:], uint8(42))
						fmt.Println(callArg.Name, " = ", ss58)
						txInItem.To = ss58
					} else if callArg.Type == "Compact<T::Balance>" {
						var argValue = types.UCompact{}
						_ = decoder.Decode(&argValue)
						fmt.Println(callArg.Name, " = ", argValue)
						argValueBigInt := big.Int(argValue)
						amount := new(big.Int)
						amount, ok := amount.SetString(argValueBigInt.String(), 10)
						if !ok {
							return fmt.Errorf("BXL: failed: unable to set amount string")
						}
						coin := Coin{DOTAsset, amount}
						txInItem.Coins = append(txInItem.Coins, coin)
					} else if callArg.Type == "Vec<u8>" {
						var argValue = types.Bytes{}
						// hex.DecodeString(a.Value.(string))
						_ = decoder.Decode(&argValue)
						value := string(argValue)
						fmt.Println("BXL: FetchTxs: Vec<u8> ", callArg.Name, "=", value)
						txInItem.Memo = value
					}
				}
			}
			fmt.Println("transaction Item: ", txInItem)
			// Add back to array of transaction items
			txInbound.TxArray = append(txInbound.TxArray, txInItem)
		}
	}
	fmt.Println("transaction txInbound: ", txInbound)

	return nil

}

func findModule(metadata *types.Metadata, index types.CallIndex) types.FunctionMetadataV4 {
	for _, mod := range metadata.AsMetadataV12.Modules {
		if mod.Index == index.SectionIndex {
			fmt.Println("Find module  ", mod.Name)
			return mod.Calls[index.MethodIndex]
		}
	}
	panic("Unknown call")
}

func NewSubstrateAPI() *gsrpc.SubstrateAPI {
	// Instantiate the API
	api, err := gsrpc.NewSubstrateAPI(config.Default().RPCURL)
	if err != nil {
		panic(err)
	}
	return api
}

func SetSerDeOptions() types.SerDeOptions {
	opts := types.SerDeOptions{NoPalletIndices: true}
	types.SetSerDeOptions(opts)
	return opts
}

func getHeight() (int64, error) {
	api := NewSubstrateAPI()
	finalizedBlockHash, err := api.RPC.Chain.GetFinalizedHead()
	if err != nil {
		return 0, err
	}

	fmt.Println("BXL: finalizedBlockHash: ", finalizedBlockHash)
	signedBlock, err := api.RPC.Chain.GetBlock(finalizedBlockHash)
	if err != nil {
		return 0, err
	}

	fmt.Println("BXL: GetHeight: ", int64(signedBlock.Block.Header.Number))
	return int64(signedBlock.Block.Header.Number), nil
}

func GetMetadataLatest(api *gsrpc.SubstrateAPI) *types.Metadata {
	meta, err := api.RPC.State.GetMetadataLatest()
	if err != nil {
		panic(err)
	}
	return meta
}

func NewAddressFromHexAccountID(hexAccountId string) types.Address {
	addr, err := types.NewAddressFromHexAccountID(hexAccountId)
	if err != nil {
		panic(err)
	}
	return addr
}

func GetGenesisHash(api *gsrpc.SubstrateAPI) types.Hash {
	genesisHash, err := api.RPC.Chain.GetBlockHash(0)
	if err != nil {
		panic(err)
	}
	return genesisHash
}

func GetRuntimeVersionLatest(api *gsrpc.SubstrateAPI) *types.RuntimeVersion {
	rv, err := api.RPC.State.GetRuntimeVersionLatest()
	if err != nil {
		panic(err)
	}
	return rv
}

func CreateStorageKey(meta *types.Metadata, pubkey []byte) types.StorageKey {
	key, err := types.CreateStorageKey(meta, "System", "Account", pubkey, nil)
	if err != nil {
		panic(err)
	}
	return key
}

func GetStorageLatest(api *gsrpc.SubstrateAPI, key types.StorageKey) types.AccountInfo {
	var accountInfo types.AccountInfo
	ok, err := api.RPC.State.GetStorageLatest(key, &accountInfo)
	if err != nil || !ok {
		panic(err)
	}
	return accountInfo
}

func CreateBalanceCall(meta *types.Metadata, toAddr types.Address, amount uint64) types.Call {
	call, err := types.NewCall(meta, "Balances.transfer", toAddr, types.NewUCompactFromUInt(1000000000000000*amount))
	if err != nil {
		panic(err)
	}
	return call
}

type EcdsaKeyringPair struct {
	// URI is the derivation path for the private key in subkey
	URI string
	// Address is an SS58 address
	Address string
	// PublicKey
	PublicKey string
	// Account Id
	AccountID []byte
}

func GetAliceEcdsaKeyringPair() EcdsaKeyringPair {
	// subkey inspect --scheme Ecdsa //Alice
	// Secret Key URI `//Alice` is account:
	//   Secret seed:      0xcb6df9de1efca7a3998a8ead4e02159d5fa99c3e0d4fd6432667390bb4726854
	//   Public key (hex): 0x020a1091341fe5664bfa1782d5e04779689068c916b04cb365ec3153755684d9a1
	//   Account ID:       0x01e552298e47454041ea31273b4b630c64c104e4514aa3643490b8aaca9cf8ed
	//   SS58 Address:     5C7C2Z5sWbytvHpuLTvzKunnnRwQxft1jiqrLD5rhucQ5S9X
	accountID, err := types.HexDecodeString("0x01e552298e47454041ea31273b4b630c64c104e4514aa3643490b8aaca9cf8ed")
	if err != nil {
		panic(err)
	}

	keypair := EcdsaKeyringPair{
		URI:       "//Alice",
		Address:   "5C7C2Z5sWbytvHpuLTvzKunnnRwQxft1jiqrLD5rhucQ5S9X",
		AccountID: accountID, // Account ID gets account info
		PublicKey: "0x020a1091341fe5664bfa1782d5e04779689068c916b04cb365ec3153755684d9a1",
	}
	return keypair
}

func transferAliceSr25519ToAliceEd25519() {
	api := NewSubstrateAPI()
	SetSerDeOptions()
	metadata := GetMetadataLatest(api)
	// $ subkey inspect --scheme Ed25519 //Alice
	// Secret Key URI `//Alice` is account:
	// Secret seed:      0xabf8e5bdbe30c65656c0a3cbd181ff8a56294a69dfedd27982aace4a76909115
	// Public key (hex): 0x88dc3417d5058ec4b4503e0c12ea1a0a89be200fe98922423d4334014fa6b0ee
	// Account ID:       0x88dc3417d5058ec4b4503e0c12ea1a0a89be200fe98922423d4334014fa6b0ee
	// SS58 Address:     5FA9nQDVg267DEd8m1ZypXLBnvN7SFxYwV7ndqSYGiN9TTpu
	aliceEd25519 := NewAddressFromHexAccountID("0x88dc3417d5058ec4b4503e0c12ea1a0a89be200fe98922423d4334014fa6b0ee")
	genesisHash := GetGenesisHash(api)
	runtimeVersion := GetRuntimeVersionLatest(api)
	storageKey := CreateStorageKey(metadata, signature.TestKeyringPairAlice.PublicKey)
	accountInfo := GetStorageLatest(api, storageKey)
	nonce := uint32(accountInfo.Nonce)

	options := types.SignatureOptions{
		BlockHash:          genesisHash,
		Era:                types.ExtrinsicEra{IsMortalEra: false},
		GenesisHash:        genesisHash,
		Nonce:              types.NewUCompactFromUInt(uint64(nonce)),
		SpecVersion:        runtimeVersion.SpecVersion,
		Tip:                types.NewUCompactFromUInt(0),
		TransactionVersion: runtimeVersion.TransactionVersion,
	}
	call := CreateBalanceCall(metadata, aliceEd25519, 10)
	ext := types.NewExtrinsic(call)
	err := ext.Sign(signature.TestKeyringPairAlice, options)
	if err != nil {
		panic(err)
	}
	hash, err := api.RPC.Author.SubmitExtrinsic(ext)
	if err != nil {
		fmt.Println(err.Error())
		panic(err)
	}
	fmt.Printf("Transfer sent with extrinsic hash %#x\n", hash)
}

func transferAliceSr25519ToAliceEcdsa() {
	api := NewSubstrateAPI()
	SetSerDeOptions()
	metadata := GetMetadataLatest(api)
	// $ subkey inspect --scheme Ecdsa //Alice
	// Secret Key URI `//Alice` is account:
	// Secret seed:      0xcb6df9de1efca7a3998a8ead4e02159d5fa99c3e0d4fd6432667390bb4726854
	// Public key (hex): 0x020a1091341fe5664bfa1782d5e04779689068c916b04cb365ec3153755684d9a1
	// Account ID:       0x01e552298e47454041ea31273b4b630c64c104e4514aa3643490b8aaca9cf8ed
	// SS58 Address:     5C7C2Z5sWbytvHpuLTvzKunnnRwQxft1jiqrLD5rhucQ5S9X
	aliceEd25519 := NewAddressFromHexAccountID("0x01e552298e47454041ea31273b4b630c64c104e4514aa3643490b8aaca9cf8ed")
	genesisHash := GetGenesisHash(api)
	runtimeVersion := GetRuntimeVersionLatest(api)
	storageKey := CreateStorageKey(metadata, signature.TestKeyringPairAlice.PublicKey)
	accountInfo := GetStorageLatest(api, storageKey)
	nonce := uint32(accountInfo.Nonce)

	options := types.SignatureOptions{
		BlockHash:          genesisHash,
		Era:                types.ExtrinsicEra{IsMortalEra: false},
		GenesisHash:        genesisHash,
		Nonce:              types.NewUCompactFromUInt(uint64(nonce)),
		SpecVersion:        runtimeVersion.SpecVersion,
		Tip:                types.NewUCompactFromUInt(0),
		TransactionVersion: runtimeVersion.TransactionVersion,
	}

	call := CreateBalanceCall(metadata, aliceEd25519, 10)
	ext := types.NewExtrinsic(call)
	err := ext.Sign(signature.TestKeyringPairAlice, options)
	if err != nil {
		panic(err)
	}
	hash, err := api.RPC.Author.SubmitExtrinsic(ext)
	if err != nil {
		fmt.Println(err.Error())
		panic(err)
	}
	fmt.Printf("Transfer sent with extrinsic hash %#x\n", hash)
}

func transferAliceEcdsaToBobSr25519() {
	api := NewSubstrateAPI()
	SetSerDeOptions()
	metadata := GetMetadataLatest(api)
	genesisHash := GetGenesisHash(api)
	runtimeVersion := GetRuntimeVersionLatest(api)

	aliceEcdsaKeyringPair := GetAliceEcdsaKeyringPair()
	storageKey := CreateStorageKey(metadata, aliceEcdsaKeyringPair.AccountID)
	accountInfo := GetStorageLatest(api, storageKey)
	nonce := uint32(accountInfo.Nonce)

	// $ subkey inspect //Bob
	// Secret Key URI `//Bob` is account:
	// Secret seed:      0x398f0c28f98885e046333d4a41c19cee4c37368a9832c6502f6cfd182e2aef89
	// Public key (hex): 0x8eaf04151687736326c9fea17e25fc5287613693c912909cb226aa4794f26a48
	// Account ID:       0x8eaf04151687736326c9fea17e25fc5287613693c912909cb226aa4794f26a48
	// SS58 Address:     5FHneW46xGXgs5mUiveU4sbTyGBzmstUspZC92UhjJM694ty
	bobSr25519 := NewAddressFromHexAccountID("0x8eaf04151687736326c9fea17e25fc5287613693c912909cb226aa4794f26a48")

	options := types.SignatureOptions{
		BlockHash:          genesisHash,
		Era:                types.ExtrinsicEra{IsMortalEra: false},
		GenesisHash:        genesisHash,
		Nonce:              types.NewUCompactFromUInt(uint64(nonce)),
		SpecVersion:        runtimeVersion.SpecVersion,
		Tip:                types.NewUCompactFromUInt(0),
		TransactionVersion: runtimeVersion.TransactionVersion,
	}

	call := CreateBalanceCall(metadata, bobSr25519, 10)
	ext := types.NewExtrinsic(call)

	// subkey inspect --scheme Ecdsa //Alice
	// Secret Key URI `//Alice` is account:
	//   Secret seed:      0xcb6df9de1efca7a3998a8ead4e02159d5fa99c3e0d4fd6432667390bb4726854
	//   Public key (hex): 0x020a1091341fe5664bfa1782d5e04779689068c916b04cb365ec3153755684d9a1
	//   Account ID:       0x01e552298e47454041ea31273b4b630c64c104e4514aa3643490b8aaca9cf8ed
	//   SS58 Address:     5C7C2Z5sWbytvHpuLTvzKunnnRwQxft1jiqrLD5rhucQ5S9X
	// sign using ecdsa

	extSigned, err := SignUsingEcdsa(ext, aliceEcdsaKeyringPair, options)
	if err != nil {
		panic(err)
	}

	hash, err := api.RPC.Author.SubmitExtrinsic(extSigned)
	if err != nil {
		fmt.Println(err.Error())
		panic(err)
	}
	fmt.Printf("Transfer sent with extrinsic hash %#x\n", hash)
}

// Sign Using Ecdsa
func SignUsingEcdsa(e types.Extrinsic, signer EcdsaKeyringPair, o types.SignatureOptions) (types.Extrinsic, error) {
	if e.Type() != types.ExtrinsicVersion4 {
		return e, fmt.Errorf("unsupported extrinsic version: %v (isSigned: %v, type: %v)", e.Version, e.IsSigned(), e.Type())
	}

	mb, err := types.EncodeToBytes(e.Method)
	if err != nil {
		return e, err
	}

	era := o.Era
	if !o.Era.IsMortalEra {
		era = types.ExtrinsicEra{IsImmortalEra: true}
	}

	payload := types.ExtrinsicPayloadV4{
		ExtrinsicPayloadV3: types.ExtrinsicPayloadV3{
			Method:      mb,
			Era:         era,
			Nonce:       o.Nonce,
			Tip:         o.Tip,
			SpecVersion: o.SpecVersion,
			GenesisHash: o.GenesisHash,
			BlockHash:   o.BlockHash,
		},
		TransactionVersion: o.TransactionVersion,
	}

	pubkey, err := types.HexDecodeString(signer.PublicKey)
	if err != nil {
		panic(err)
	}
	signerPubKey := types.NewAddressFromAccountID(pubkey)

	// You would use this if you are using Ecdsa/ Ed25519 since it needs to return bytes
	data, err := types.EncodeToBytes(payload)
	if err != nil {
		return e, err
	}

	sig, err := SignEcdsa(data, signer, "Ecdsa")
	if err != nil {
		return e, err
	}
	multiSig := types.MultiSignature{IsEcdsa: true, AsEcdsa: sig}

	// multiSig := types.MultiSignature{IsEd25519: true, AsEd25519: sig}
	// You would use this if you are using Ecdsa since it needs to return bytes

	extSig := types.ExtrinsicSignatureV4{
		Signer:    signerPubKey,
		Signature: multiSig,
		Era:       era,
		Nonce:     o.Nonce,
		Tip:       o.Tip,
	}

	e.Signature = extSig

	// mark the extrinsic as signed
	e.Version |= types.ExtrinsicBitSigned

	return e, nil

}

func SignEcdsa(data []byte, signer EcdsaKeyringPair, scheme string) ([]byte, error) {
	// if data is longer than 256 bytes, hash it first
	if len(data) > 256 {
		h := blake2b.Sum256(data)
		data = h[:]
	}

	// use "subkey" command for signature
	cmd := exec.Command("subkey", "sign", "--hex", "--scheme", scheme, "--suri", signer.URI)

	// data to stdin
	dataHex := hex.EncodeToString(data)
	cmd.Stdin = strings.NewReader(dataHex)

	log.Printf("echo -n \"%v\" | %v sign  --hex --scheme %v --suri %v ", dataHex, "subkey", scheme, signer.URI)

	// execute the command, get the output
	out, err := cmd.Output()
	if err != nil {
		return []byte{}, fmt.Errorf("failed to sign with subkey: %v", err.Error())
	}

	// remove line feed
	if len(out) > 0 && out[len(out)-1] == 10 {
		out = out[:len(out)-1]
	}

	outStr := string(out)

	dec, err := hex.DecodeString(outStr)
	log.Printf("echo -n \"%v\" | subkey verify --hex --scheme %v %v %v ", dataHex, scheme, outStr, signer.PublicKey)

	return dec, err

}

func GetAliceEd25519KeyringPair() signature.KeyringPair {
	// subkey inspect --scheme Ed25519 //Alice
	// Secret Key URI `//Alice` is account:
	// Secret seed:      0xabf8e5bdbe30c65656c0a3cbd181ff8a56294a69dfedd27982aace4a76909115
	// Public key (hex): 0x88dc3417d5058ec4b4503e0c12ea1a0a89be200fe98922423d4334014fa6b0ee
	// Account ID:       0x88dc3417d5058ec4b4503e0c12ea1a0a89be200fe98922423d4334014fa6b0ee
	// SS58 Address:     5FA9nQDVg267DEd8m1ZypXLBnvN7SFxYwV7ndqSYGiN9TTpu
	publicKey, err := types.HexDecodeString("0x88dc3417d5058ec4b4503e0c12ea1a0a89be200fe98922423d4334014fa6b0ee")
	if err != nil {
		panic(err)
	}

	keypair := signature.KeyringPair{
		URI:       "//Alice",
		Address:   "5FA9nQDVg267DEd8m1ZypXLBnvN7SFxYwV7ndqSYGiN9TTpu",
		PublicKey: publicKey,
	}
	return keypair
}

func transferAliceEd25519ToBobSr25519() {
	api := NewSubstrateAPI()
	SetSerDeOptions()
	metadata := GetMetadataLatest(api)
	genesisHash := GetGenesisHash(api)
	runtimeVersion := GetRuntimeVersionLatest(api)

	aliceEd25519KeyringPair := GetAliceEd25519KeyringPair()
	storageKey := CreateStorageKey(metadata, aliceEd25519KeyringPair.PublicKey)
	accountInfo := GetStorageLatest(api, storageKey)
	nonce := uint32(accountInfo.Nonce)

	// $ subkey inspect //Bob
	// Secret Key URI `//Bob` is account:
	// Secret seed:      0x398f0c28f98885e046333d4a41c19cee4c37368a9832c6502f6cfd182e2aef89
	// Public key (hex): 0x8eaf04151687736326c9fea17e25fc5287613693c912909cb226aa4794f26a48
	// Account ID:       0x8eaf04151687736326c9fea17e25fc5287613693c912909cb226aa4794f26a48
	// SS58 Address:     5FHneW46xGXgs5mUiveU4sbTyGBzmstUspZC92UhjJM694ty
	bobSr25519 := NewAddressFromHexAccountID("0x8eaf04151687736326c9fea17e25fc5287613693c912909cb226aa4794f26a48")

	options := types.SignatureOptions{
		BlockHash:          genesisHash,
		Era:                types.ExtrinsicEra{IsMortalEra: false},
		GenesisHash:        genesisHash,
		Nonce:              types.NewUCompactFromUInt(uint64(nonce)),
		SpecVersion:        runtimeVersion.SpecVersion,
		Tip:                types.NewUCompactFromUInt(0),
		TransactionVersion: runtimeVersion.TransactionVersion,
	}

	call := CreateBalanceCall(metadata, bobSr25519, 3)
	ext := types.NewExtrinsic(call)

	// sign using Ed25519
	extSigned, err := SignUsingEd25519(ext, aliceEd25519KeyringPair, options)
	if err != nil {
		panic(err)
	}

	hash, err := api.RPC.Author.SubmitExtrinsic(extSigned)
	if err != nil {
		fmt.Println(err.Error())
		panic(err)
	}
	fmt.Printf("Transfer sent with extrinsic hash %#x\n", hash)
}

func SignUsingEd25519(e types.Extrinsic, signer signature.KeyringPair, o types.SignatureOptions) (types.Extrinsic, error) {
	if e.Type() != types.ExtrinsicVersion4 {
		return e, fmt.Errorf("unsupported extrinsic version: %v (isSigned: %v, type: %v)", e.Version, e.IsSigned(), e.Type())
	}

	mb, err := types.EncodeToBytes(e.Method)
	if err != nil {
		return e, err
	}

	era := o.Era
	if !o.Era.IsMortalEra {
		era = types.ExtrinsicEra{IsImmortalEra: true}
	}

	payload := types.ExtrinsicPayloadV4{
		ExtrinsicPayloadV3: types.ExtrinsicPayloadV3{
			Method:      mb,
			Era:         era,
			Nonce:       o.Nonce,
			Tip:         o.Tip,
			SpecVersion: o.SpecVersion,
			GenesisHash: o.GenesisHash,
			BlockHash:   o.BlockHash,
		},
		TransactionVersion: o.TransactionVersion,
	}

	signerPubKey := types.NewAddressFromAccountID(signer.PublicKey)

	data, err := types.EncodeToBytes(payload)
	if err != nil {
		return e, err
	}

	sig, err := SignEd25519(data, signer, "Ed25519")
	if err != nil {
		return e, err
	}

	multiSig := types.MultiSignature{IsEd25519: true, AsEd25519: sig}

	// multiSig := types.MultiSignature{IsEd25519: true, AsEd25519: sig}
	// You would use this if you are using Ecdsa since it needs to return bytes

	extSig := types.ExtrinsicSignatureV4{
		Signer:    signerPubKey,
		Signature: multiSig,
		Era:       era,
		Nonce:     o.Nonce,
		Tip:       o.Tip,
	}

	e.Signature = extSig

	// mark the extrinsic as signed
	e.Version |= types.ExtrinsicBitSigned

	return e, nil

}

func SignEd25519(data []byte, signer signature.KeyringPair, scheme string) (types.Signature, error) {
	// if data is longer than 256 bytes, hash it first
	if len(data) > 256 {
		h := blake2b.Sum256(data)
		data = h[:]
	}

	// use "subkey" command for signature
	cmd := exec.Command("subkey", "sign", "--hex", "--scheme", scheme, "--suri", signer.URI)
	// cmd := exec.Command("subkey", "sign", "--hex", "--suri", privateKeyURI)

	// data to stdin
	dataHex := hex.EncodeToString(data)
	cmd.Stdin = strings.NewReader(dataHex)

	log.Printf("echo -n \"%v\" | %v sign  --hex --scheme %v --suri %v ", dataHex, "subkey", scheme, signer.URI)

	// execute the command, get the output
	out, err := cmd.Output()
	if err != nil {
		return types.Signature{}, fmt.Errorf("failed to sign with subkey: %v", err.Error())
	}

	// remove line feed
	if len(out) > 0 && out[len(out)-1] == 10 {
		out = out[:len(out)-1]
	}

	outStr := string(out)

	dec, err := hex.DecodeString(outStr)

	hxpubkey := hex.EncodeToString(signer.PublicKey)
	log.Printf("echo -n \"%v\" | subkey verify --hex --scheme %v %v %v ", dataHex, scheme, outStr, hxpubkey)

	// Return a new Signature
	return types.NewSignature(dec), err

}
