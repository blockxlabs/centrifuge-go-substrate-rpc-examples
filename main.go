package main

import (
	"encoding/hex"
	"fmt"
	"log"
	"os/exec"
	"strings"

	gsrpc "github.com/centrifuge/go-substrate-rpc-client"
	"github.com/centrifuge/go-substrate-rpc-client/config"
	"github.com/centrifuge/go-substrate-rpc-client/signature"
	"github.com/centrifuge/go-substrate-rpc-client/types"
	"github.com/minio/blake2b-simd"
)

func main() {
	//Send Tokens from Sr25519 account to Ed25519
	transferAliceSr25519ToAliceEd25519()

	// Send Tokens from Sr25519 account to Ecdsa
	// transferAliceSr25519ToAliceEcdsa()

	// Currently: Invalid Transaction returns
	// Send Tokens from Ecdsa to Sr25519
	// transferAliceEcdsaToBobSr25519()

	// TODO:
	// Send Tokens from Ecsda to Ed25519
	// transferAliceEcdsaToBobEd25519()

	// Send Tokens from Ed25519 to Shnorkell
	transferAliceEd25519ToBobSr25519()

	// TODO:
	// Send Tokens from Ed25519 to Ecdsa
	// transferAliceEd25519ToBobEcdsa()
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
