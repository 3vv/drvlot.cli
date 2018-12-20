// h 20180923
//
// Command Line Interface

package main

import (
	"bcp/eth"
	"bufio"
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"unsafe"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/zieckey/goini"
	. "gopkg.in/urfave/cli.v1"
)

const (
	// Config
	cliCfg = "../../cfg/eth/cli.ini"
	// Config section
	cli         = "cli"
	genesis     = "genesis"
	version     = "version"
	api         = "api"
	gas         = "gas"
	account     = "account"
	block       = "block"
	transaction = "transaction"
	event       = "event"
	// Config key
	debug           = "debug"
	ipc             = "ipc"
	ipcenable       = "ipcenable"
	rpc             = "rpc"
	coinbase        = "coinbase"
	acc             = "acc"
	pwd             = "pwd"
	FTO             = "FTO"
	netVersion      = "netVersion"
	protocolVersion = "protocolVersion"
	clientVersion   = "clientVersion"
	gasPrice        = "gasPrice"
	blockHeight     = "blockHeight"
	// HEX prefix
	hex = "0x"
)

var (
	ini *goini.INI
	bcp *eth.Client
	adr common.Address
)

func init() {
	for {
		_ini, err := goini.LoadInheritedINI(PWD() + cliCfg) // goini.New()
		if err != nil {
			//fmt.Printf("Failed to parse config: %v\n\n", err.Error())
			//break
			_ini, err = goini.LoadInheritedINI(PWD() + "cli.ini")
			if err != nil {
				fmt.Printf("Failed to parse config: %v\n\n", err.Error())
				break
			}
		}
		ini = _ini
		url, ok := ini.SectionGet(api, rpc) // ini.Get(rpc)
		if !ok {
			break
		}
		fmt.Printf("Connect to %v ...\n\n", url)
		bcp = eth.NewClient(url, nil)
		//
		// Finally
		if true {
			break
		}
	}
}

// runtime.Caller(1)
func PWD() string {
	ret := ""
	for {
		file, err := exec.LookPath(os.Args[0])
		if err != nil {
			break
		}
		path, err := filepath.Abs(file)
		if err != nil {
			break
		}
		i := strings.LastIndex(path, string(filepath.Separator))
		if i < 0 {
			break
		}
		// Default
		ret = string(path[0 : i+1])
		//
		// Finally
		if true {
			break
		}
	}
	return ret
}

func writeCfg(s, k, v string) {
	ini.SectionSet(s, k, v) // ini.Set(k, v)
	val, ok := ini.SectionGet(cli, debug)
	if !ok {
		val = "1"
	}
	var f io.Writer = os.Stdout
	if val != "1" {
		_f, e := os.OpenFile(cliCfg, os.O_CREATE|os.O_TRUNC|os.O_RDWR, 0644)
		if e == nil {
			defer _f.Close()
			f = _f
		}
	}
	writer := bufio.NewWriter(f)
	ini.Write(writer)
	writer.Flush()
}

func setCfg(s, k, v string) {
	ini.SectionSet(s, k, v)
}

func printAccounts() {
	a, _ := bcp.EthAccounts()
	fmt.Print("[")
	n := len(a)
	for i := 0; i < n; i++ {
		if i == 0 {
			adr = a[0]
		}
		if i != 0 {
			fmt.Print(",")
		}
		fmt.Printf("%s%s%s", "\"", a[i].String(), "\"")
	}
	fmt.Print("]\n")
}

func setAcc(_acc, _pwd string) string {
	if strings.HasPrefix(_acc, hex) {
		adr = common.StringToAddress(_acc)
	} else {
		_coinbase, _ := bcp.EthCoinbase()
		adr = _coinbase
		_acc = _coinbase.String()
		setCfg(genesis, coinbase, _acc)
	}
	if _pwd != "" {
		setCfg(account, pwd, _pwd)
	}
	writeCfg(account, acc, _acc)
	return _acc
}

func setFTO(_fto string) string {
	if strings.HasPrefix(_fto, hex) {
		writeCfg(account, FTO, _fto)
		return _fto
	} else {
		return ""
	}
}

func printMISC() {
	_protocolVersion, _ := bcp.EthProtocolVersion()
	_clientVersion, _ := bcp.Web3ClientVersion()
	_netVersion, _ := bcp.NetVersion()
	_coinbase, _ := bcp.EthCoinbase()
	_acc := _coinbase.String()
	_gasPrice, _ := bcp.EthGasPrice()
	estimateGas, _ := bcp.EthEstimateGas(eth.EstimateTransactionGasRequest)
	estimateContractGas, _ := bcp.EthEstimateGas(eth.EstimateContractGasRequest)
	netListening, _ := bcp.NetListening()
	netPeerCount, _ := bcp.NetPeerCount()
	syncing, _ := bcp.EthSyncing()
	mining, _ := bcp.EthMining()
	hashrate, _ := bcp.EthHashrate()
	work, _ := bcp.EthGetWork()
	blockNumber, _ := bcp.EthBlockNumber()
	fmt.Printf("%s: %s\n", protocolVersion, _protocolVersion)
	fmt.Printf("%s: %s\n", clientVersion, _clientVersion)
	fmt.Printf("%s: %s\n", netVersion, _netVersion)
	fmt.Printf("%s: %s\n", "estimateGas", estimateGas)
	fmt.Printf("%s: %s\n", "estimateContractGas", estimateContractGas)
	fmt.Printf("%s: %t\n", "netListening", netListening)
	fmt.Printf("%s: %s\n", "netPeerCount", netPeerCount)
	fmt.Printf("%s: %t\n", "syncing", syncing)
	fmt.Printf("%s: %t %s: %s\n", "mining", mining, coinbase, _acc)
	fmt.Printf("%s: %v\n", "hashrate", hashrate)
	fmt.Printf("%s: %v\n", "work", work)
	fmt.Printf("%s: %v\n", blockHeight, blockNumber)
	setCfg(version, protocolVersion, _protocolVersion)
	setCfg(version, clientVersion, _clientVersion)
	setCfg(version, netVersion, _netVersion)
	setCfg(genesis, coinbase, _acc)
	setCfg(gas, gasPrice, _gasPrice.String())
	writeCfg(block, blockHeight, blockNumber.String())
}

func Any2Bytes(any interface{}) []byte {
	buf := new(bytes.Buffer)
	binary.Write(buf, binary.LittleEndian, any)
	return buf.Bytes()
}

func Bytes2String(b []byte) string {
	bh := (*reflect.SliceHeader)(unsafe.Pointer(&b))
	sh := reflect.StringHeader{Data: bh.Data, Len: bh.Len}
	return *(*string)(unsafe.Pointer(&sh))
}

func String2Bytes(s string) []byte {
	sh := (*reflect.StringHeader)(unsafe.Pointer(&s))
	bh := reflect.SliceHeader{Data: sh.Data, Len: sh.Len, Cap: 0}
	return *(*[]byte)(unsafe.Pointer(&bh))
}

func Bytes2Hex(b []byte) string { return hexutil.Encode(b) }

func Hex2Bytes(s string) ([]byte, error) { return hexutil.Decode(s) }

func Big2Hex(big *big.Int) string { return hexutil.EncodeBig(big) }

func Hex2Big(hex string) *big.Int {
	big, err := hexutil.DecodeBig(hex)
	if err == nil {
		return big
	} else {
		return nil
	}
}

func Num2Hex(str string) string {
	var u64 uint64
	if strings.HasPrefix(str, hex) {
		str = strings.TrimPrefix(str, hex)
		v, _ := strconv.ParseUint(str, 16, 64)
		u64 = v
	} else {
		v, _ := strconv.ParseUint(str, 10, 64)
		u64 = v
	}
	return hex + strconv.FormatUint(u64, 16)
}

func Hex2Num(hex string) string {
	big, _ := hexutil.DecodeBig(hex)
	if big != nil {
		return big.String()
	} else {
		return zeroInt
	}
}

func s2f(str string) float64 { f, _ := strconv.ParseFloat(str, 64); return f }

func f2s(f float64) string { return fmt.Sprintf("%.17f", f) }

func Contains(set interface{}, ele interface{}) bool {
	setValue := reflect.ValueOf(set)
	switch reflect.TypeOf(set).Kind() {
	case reflect.Array, reflect.Slice:
		n := setValue.Len()
		var v interface{}
		for i := 0; i < n; i++ {
			v = setValue.Index(i).Interface()
			if v != ele {
				continue
			}
			return true
		}
	case reflect.Map:
		return setValue.MapIndex(reflect.ValueOf(ele)).IsValid()
	}
	return false
}

const (
	zeroInt    = "0"
	zeroFloat  = "0.0"
	zeroSha1   = "0x0000000000000000000000000000000000000000"
	zeroSha256 = "0x0000000000000000000000000000000000000000000000000000000000000000"
)

var (
	wei       = big.NewInt(1)
	Kwei      = big.NewInt(1000)
	Mwei      = big.NewInt(1000000)
	Gwei      = big.NewInt(1000000000)
	KGwei     = big.NewInt(1000000000000)
	MGwei     = big.NewInt(1000000000000000)
	GGwei     = big.NewInt(1000000000000000000)
	bigInt    = new(big.Int)
	bigFloat  = new(big.Float)
	bigFloat2 = new(big.Float)
)

func fromWei(number, unit *big.Int) *big.Float {
	return bigFloat.Quo(bigFloat.SetInt(number), bigFloat2.SetInt(unit))
}

func toWei(number *big.Float, unit *big.Int) *big.Int {
	v, _ := bigFloat.Mul(bigFloat.Set(number), bigFloat2.SetInt(unit)).Int(&big.Int{})
	return v
}

const defaultAddress = zeroSha1

func addressing(adr string) string {
	ret := defaultAddress
	if adr == "" {
		v, ok := ini.SectionGet(account, acc)
		if ok {
			ret = v
		} else {
			ret = setAcc("", "")
		}
	} else {
		if strings.HasPrefix(adr, hex) && common.IsHexAddress(adr) {
			ret = adr
		}
	}
	return ret
}

const defaultIndex = "0x0"

func indexing(idx string) string {
	for {
		if strings.HasPrefix(idx, hex) && common.IsHex(idx) {
			break
		}
		// Default
		idx = defaultIndex
		//
		// Finally
		if true {
			break
		}
	}
	return idx
}

/*
defaultBlock parameter
  HEX String - an integer block number
  String "earliest" for the earliest/genesis block
  String "latest" - for the latest mined block
  String "pending" - for the pending state/transactions
*/
const (
	latest       = "latest"
	pending      = "pending"
	earliest     = "earliest"
	defaultBlock = latest
)

var preferBlock = []string{earliest, pending, earliest}

func blocking(blk string) string {
	for {
		if Contains(preferBlock, blk) {
			break
		}
		if strings.HasPrefix(blk, hex) && common.IsHex(blk) {
			break
		}
		// Default
		blk = defaultBlock
		//
		// Finally
		if true {
			break
		}
	}
	return blk
}

// `api`
var (
	// `ipc` action
	ipcAction = func(c *Context) error {
		sts := "true"
		if c.Args().Get(1) == "" {
			sts = "false"
		}
		ini.SectionSet(api, ipc, c.Args().First())
		writeCfg(api, ipcenable, sts)
		val, ok := ini.SectionGet(api, ipc)
		fmt.Printf("Set IPC socket/pipe (enable=%s) %s %t to %s\n", sts, val, ok, cliCfg)
		return nil
	}
	// `rpc` action
	rpcAction = func(c *Context) error {
		writeCfg(api, rpc, c.Args().First())
		val, ok := ini.SectionGet(api, rpc)
		fmt.Printf("Set RPC host & port %s %t to %s\n", val, ok, cliCfg)
		return nil
	}
	// `api` command
	apiCommand = Command{
		Name: "api", Usage: "Set API and console options",
		Subcommands: []Command{{
			Name: "ipc", Usage: "Set IPC socket/pipe within the datadir (e.g. ./cli api ipc ./geth.ipc enable)",
			Action: ipcAction,
		}, {
			Name: "rpc", Usage: "Set RPC host & port (e.g. ./cli api rpc http://`ifc`:8545)",
			Action: rpcAction,
		}},
	}
)

// `acc`
var (
	// `acc` action
	accAction = func(c *Context) error {
		par := c.Args()
		fmt.Printf("Set default account to %s\n", setAcc(par.First(), par.Get(1)))
		return nil
	}
	// `acc` command
	accCommand = Command{
		Name: "acc", Usage: "Set default account",
		Action: accAction,
	}
)

// `FTO`, `fto`
var (
	// `fto` action
	ftoAction = func(c *Context) error {
		_fto := setFTO(c.Args().First())
		if _fto != "" {
			fmt.Printf("Set default FTO account to %s\n", _fto)
		}
		return nil
	}
	// `fto` command
	ftoCommand = Command{
		Name: "FTO", Aliases: []string{"fto"}, Usage: "Set default FTO account",
		Action: ftoAction,
	}
)

// `accounts`
var (
	// `accounts` action
	accountsAction = func(c *Context) error {
		printAccounts()
		setAcc("", "")
		return nil
	}
	// `accounts` command
	accountsCommand = Command{
		Name: "accounts", Aliases: []string{"accs"}, Usage: "List accounts",
		Action: accountsAction,
	}
)

// `MISC`, `misc`
var (
	// `misc` action
	miscAction = func(c *Context) error {
		printMISC()
		return nil
	}
	// `misc` command
	miscCommand = Command{
		Name: "MISC", Aliases: []string{"misc"}, Usage: "List miscellaneous items",
		Action: miscAction,
	}
)

// `big`
var (
	// `big` flags
	bigEncodeFlag = StringFlag{
		Name:  "e",
		Usage: "encode the given data",
		//Value: "",
	}
	bigDecodeFlag = StringFlag{
		Name:  "d",
		Usage: "decode the given data",
		//Value: "",
	}
	bigFlags = []Flag{
		bigEncodeFlag,
		bigDecodeFlag,
	}
	// `big` action
	bigAction = migrateFlags(func(c *Context) error {
		flg := ""
		par := c.Args().First()
		if v := c.GlobalString("e"); v != "" {
			flg = "-e"
			par = v
		}
		if v := c.GlobalString("d"); v != "" {
			flg = "-d"
			par = v
		}
		switch flg {
		default:
			if par == "" {
				par = "0"
			}
			fallthrough
		case "-e":
			big, _ := new(big.Int).SetString(par, 10)
			hex := "<n/a>"
			if big != nil {
				hex = Big2Hex(big)
			}
			fmt.Printf("%s\n", hex)
		case "-d":
			fmt.Println(Hex2Big(par))
		}
		return nil
	})
	// `big` command
	bigCommand = Command{
		Name: "big", Usage: "Encode bigint as a hex string with 0x prefix, or decode it as a quantity",
		Action: bigAction,
		Flags:  bigFlags,
	}
)

// `hex`
var (
	// `hex` flags
	hexEncodeFlag = StringFlag{
		Name:  "e",
		Usage: "encode the given data",
		//Value: "",
	}
	hexDecodeFlag = StringFlag{
		Name:  "d",
		Usage: "decode the given data",
		//Value: "",
	}
	hexFlags = []Flag{
		hexEncodeFlag,
		hexDecodeFlag,
	}
	// `hex` action
	hexAction = migrateFlags(func(c *Context) error {
		flg := ""
		par := c.Args().First()
		if v := c.GlobalString("e"); v != "" {
			flg = "-e"
			par = v
		}
		if v := c.GlobalString("d"); v != "" {
			flg = "-d"
			par = v
		}
		switch flg {
		default:
			fallthrough
		case "-e":
			fmt.Printf("%s\n", Bytes2Hex(String2Bytes(par)))
		case "-d":
			b, _ := Hex2Bytes(par)
			fmt.Println(b)
			fmt.Println(Bytes2String(b))
		}
		return nil
	})
	// `hex` command
	hexCommand = Command{
		Name: "hex", Usage: "Return hexadecimal (0x...) of the given string, or decode the given data",
		Action: hexAction,
		Flags:  hexFlags,
	}
)

// `sha`
var (
	// `sha` action
	shaAction = func(c *Context) error {
		sha, _ := bcp.Web3Sha3(c.Args().First())
		fmt.Printf("%s\n", sha)
		return nil
	}
	// `sha` command
	shaCommand = Command{
		Name: "sha", Usage: "Return Keccak-256 (not the standardized SHA3-256) of the given data",
		Action: shaAction,
	}
)

// `sign`
var (
	// `sign` action
	signAction = func(c *Context) error {
		_acc, ok := ini.SectionGet(account, acc)
		if !ok {
			_acc = setAcc("", "")
		}
		sign, err := bcp.EthSign(_acc, c.Args().First())
		fmt.Printf("%s %v\n", Bytes2Hex(sign), err)
		return nil
	}
	// `sign` command
	signCommand = Command{
		Name: "sign", Usage: "Signature with sign(keccak256(\"\\x19Ethereum Signed Message:\\n\" + len(message) + message)))",
		Action: signAction,
	}
)

// `code`
var (
	// `code` action
	codeAction = func(c *Context) error {
		par := c.Args()
		_adr := addressing(par.First())
		_blk := blocking(par.Get(1))
		v, _ := bcp.EthGetCode(_adr, _blk)
		fmt.Println(v)
		fmt.Printf("Code of %s in %s: %v\n", _adr, _blk, v)
		return nil
	}
	// `code` command
	codeCommand = Command{
		Name: "code", Usage: "Return code at a given address & block",
		Action: codeAction,
	}
)

// `storage`
var (
	// `storage` action
	storageAction = func(c *Context) error {
		par := c.Args()
		_adr := addressing(par.First())
		_idx := indexing(par.Get(1))
		_blk := blocking(par.Get(2))
		v, _ := bcp.EthGetStorageAt(_adr, _idx, _blk)
		fmt.Println(v)
		fmt.Printf("Storage at %s + %s in %s: %v\n", _adr, _idx, _blk, v)
		return nil
	}
	// `storage` command
	storageCommand = Command{
		Name: "storage", Usage: "Return the value from a storage position at a given address + index in block",
		Action: storageAction,
	}
)

// `balance`
var (
	// `balance` action
	balanceAction = func(c *Context) error {
		_acc := addressing(c.Args().First())
		v, _ := bcp.EthGetBalance(_acc, "latest")
		fmt.Println(v)
		fmt.Printf("Balance of %s: %.17f\n", _acc, fromWei(v.ToInt(), GGwei))
		return nil
	}
	// `balance` command
	balanceCommand = Command{
		Name: "balance", Aliases: []string{"bal"}, Usage: "Get balance",
		Action: balanceAction,
	}
)

// `block`, `blk`
var (
	// `blk` flags
	blkNumberFlag = StringFlag{
		Name:  "N",
		Usage: "want number",
		//Value: "",
	}
	blkHashFlag = StringFlag{
		Name:  "S",
		Usage: "want sha256",
		//Value: "",
	}
	blkNumberTxnCountFlag = StringFlag{
		Name:  "n",
		Usage: "want number for transaction count",
		//Value: "",
	}
	blkHashTxnCountFlag = StringFlag{
		Name:  "s",
		Usage: "want sha256 for transaction count",
		//Value: "",
	}
	blkFlags = []Flag{
		blkNumberFlag,
		blkHashFlag,
		blkNumberTxnCountFlag,
		blkHashTxnCountFlag,
	}
	// `blk` action
	blkAction = func(c *Context) error {
		flg := ""
		par := c.Args().First()
		if v := c.String("N"); v != "" {
			flg = "-N"
			par = v
		}
		if v := c.String("S"); v != "" {
			flg = "-S"
			par = v
		}
		if v := c.String("n"); v != "" {
			flg = "-n"
			par = v
		}
		if v := c.String("s"); v != "" {
			flg = "-s"
			par = v
		}
		switch flg {
		default:
			v, _ := bcp.EthBlockNumber()
			fmt.Println(v)
			fmt.Println(v.ToInt())
		case "-N":
			v, _ := bcp.EthGetBlockByNumber(Num2Hex(par), true)
			fmt.Println(v)
			fmt.Println(Bytes2String(v))
		case "-S":
			big := Hex2Big(par)
			if big != nil && big.UnmarshalJSON(String2Bytes(par)) == nil {
				v, _ := bcp.EthGetBlockByHash(par, true)
				fmt.Println(v)
				fmt.Println(Bytes2String(v))
			} else {
				fmt.Printf("%s %v\n", "0x0", nil)
			}
		case "-n":
			v, _ := bcp.EthGetBlockTransactionCountByNumber(Num2Hex(par))
			fmt.Println(v)
			fmt.Println(v.ToInt())
		case "-s":
			big := Hex2Big(par)
			if big != nil && big.UnmarshalJSON(String2Bytes(par)) == nil {
				fmt.Println(bcp.EthGetBlockTransactionCountByHash(par))
			} else {
				fmt.Printf("%s %v\n", "0x0", nil)
			}
		}
		return nil
	}
	// `blk` command
	blkCommand = Command{
		Name: "block", Aliases: []string{"blk"}, Usage: "Get somethings in a block",
		Action: blkAction,
		Flags:  blkFlags}
)

// `transaction`, `txn`
var ( // eth_getTransactionCount N-eth_getTransactionByBlockNumberAndIndex S-eth_getTransactionByBlockHashAndIndex
	// s-eth_getTransactionByHash r-eth_getTransactionReceipt t-eth_sendTransaction o-eth_sendRawTransaction
	// `txn` flags
	txnNumberFlag = StringFlag{
		Name:  "N",
		Usage: "want number",
		//Value: "",
	}
	txnHashFlag = StringFlag{
		Name:  "S",
		Usage: "want sha256",
		//Value: "",
	}
	txnHashTxnFlag = StringFlag{
		Name:  "s",
		Usage: "want sha256 for transaction information",
		//Value: "",
	}
	txnHashTxnReceiptFlag = StringFlag{
		Name:  "r",
		Usage: "want sha256 for transaction receipt",
		//Value: "",
	}
	txnOnlineFlag = StringFlag{
		Name:  "t",
		Usage: "call transaction or a contract creation (if the data field contains code)",
		//Value: "",
	}
	txnOfflineFlag = StringFlag{
		Name:  "o",
		Usage: "call transaction or a contract creation for signed transactions",
		//Value: "",
	}
	txnFlags = []Flag{
		txnNumberFlag,
		txnHashFlag,
		txnHashTxnFlag,
		txnHashTxnReceiptFlag,
		txnOnlineFlag,
		txnOfflineFlag,
	}
	// `txn` action
	txnAction = func(c *Context) error {
		par := c.Args()
		fmt.Println(par)
		flg := ""
		val := par.First()
		if v := c.String("N"); v != "" {
			flg = "-N"
			val = v
		}
		if v := c.String("S"); v != "" {
			flg = "-S"
			val = v
		}
		if v := c.String("s"); v != "" {
			flg = "-s"
			val = v
		}
		if v := c.String("r"); v != "" {
			flg = "-r"
			val = v
		}
		if v := c.String("t"); v != "" {
			flg = "-t"
			val = v
		}
		if v := c.String("o"); v != "" {
			flg = "-o"
			val = v
		}
		switch flg {
		default:
			pa1 := addressing(par.First())
			pa2 := blocking(par.Get(1))
			v, _ := bcp.EthGetTransactionCount(pa1, pa2)
			fmt.Println(v)
			fmt.Printf("Nonce of %s at %s: %v\n", pa1, pa2, v.ToInt())
		case "-N":
			v, _ := bcp.EthGetTransactionByBlockNumberAndIndex(Num2Hex(val), indexing(par.First()))
			fmt.Println(v)
			fmt.Println(Bytes2String(v))
		case "-S":
			big := Hex2Big(val)
			if big != nil && big.UnmarshalJSON(String2Bytes(val)) == nil {
				v, _ := bcp.EthGetTransactionByBlockHashAndIndex(val, indexing(par.First()))
				fmt.Println(v)
				fmt.Println(Bytes2String(v))
			} else {
				fmt.Printf("%s %v\n", "0x0", nil)
			}
		case "-s":
			big := Hex2Big(val)
			if big != nil && big.UnmarshalJSON(String2Bytes(val)) == nil {
				v, _ := bcp.EthGetTransactionByHash(val)
				fmt.Println(v)
				fmt.Println(Bytes2String(v))
			} else {
				fmt.Printf("%s %v\n", "0x0", nil)
			}
		case "-r":
			big := Hex2Big(val)
			if big != nil && big.UnmarshalJSON(String2Bytes(val)) == nil {
				v, _ := bcp.EthGetTransactionReceipt(val)
				fmt.Println(v)
				fmt.Println(Bytes2String(v))
			} else {
				fmt.Printf("%s %v\n", "0x0", nil)
			}
		case "-t":
			_fto := par.First()
			if _fto == "" {
				v, _ := ini.SectionGet(account, FTO)
				_fto = v
			}
			to := common.StringToAddress(_fto)
			_acc, _ := ini.SectionGet(account, acc)
			req := &eth.TransactionRequest{
				From:  common.StringToAddress(_acc),
				To:    &to,
				Value: (*hexutil.Big)(toWei(bigFloat.SetFloat64(s2f(val)), GGwei))}
			//v, _ := bcp.EthSendTransaction(Bytes2String(txn))
			fmt.Println(bcp.EthSendTransaction(req))
		case "-o":
			// # personal.unlockAccount(eth.accounts[0])
			// $ curl -X POST -H "Content-Type: application/json" --data '{"jsonrpc":"2.0","method":"eth_sendTransaction","params":[{"from":"0x333bBbA3B013ee5030375Bae31E795B2Ae083BCA","to":"0xd44695e43db0bfd5c7acdf8fb7f966d6b840672f","value":"0x1","data":"0x347465737453656e645261775472616e73616374696f6e"}],"id":1}' http://172.16.3.186:8545/
			// ./cli txn
			// ./cli hex {"to":"0xd44695e43db0bfd5c7acdf8fb7f966d6b840672f","value":"0x1","gas":"0x76c0","gasPrice":"0x9184e72a000","nonce":"0xe","data":"0x347465737453656e645261775472616e73616374696f6e"}
			//  ./cli txn -o 0x...
			//v, _ := bcp.EthSendRawTransaction(String2Bytes(val))
			v, e := bcp.EthSendRawTransaction(val)
			fmt.Printf("%v %v\n", v, e)
			fmt.Println(Bytes2Hex(Any2Bytes(v)))
		}
		return nil
	}
	// `txn` command
	txnCommand = Command{
		Name: "transaction", Aliases: []string{"txn"}, Usage: "Get/put somethings for a transaction",
		Action: txnAction,
		Flags:  txnFlags}
)

// `event`, `evt`
var ( // b-eth_newBlockFilter p-eth_newPendingTransactionFilter t-eth_newFilter
	// c-eth_getFilterChanges u-eth_uninstallFilter l-eth_getFilterLogs o-eth_getLogs
	// `evt` flags
	evtBlockFlag = StringFlag{
		Name:  "b",
		Usage: "create a filter in the node, to notify when new blocks arrives",
		//Value: "",
	}
	evtPdTxnFlag = StringFlag{
		Name:  "p",
		Usage: "create a filter in the node, to notify when new pending transactions arrive",
		//Value: "",
	}
	evtTopicFlag = StringFlag{
		Name:  "t",
		Usage: "create a filter based on specifying topic filter options, to notify when the state changes (logs)",
		//Value: "",
	}
	evtChangesFlag = StringFlag{
		Name:  "c",
		Usage: "polling for a filter, which return an array of logs which occurred since last poll",
		//Value: "",
	}
	evtUninstallFlag = StringFlag{
		Name:  "u",
		Usage: "uninstall a filter with given id (Should always be called when watch is no longer needed)",
		//Value: "",
	}
	evtLogsFlag = StringFlag{
		Name:  "l",
		Usage: "return an array of all logs matching filter with given id",
		//Value: "",
	}
	evtObjectFlag = StringFlag{
		Name:  "o",
		Usage: "return an array of all logs matching a given filter object",
		//Value: "",
	}
	evtFlags = []Flag{
		evtBlockFlag,
		evtPdTxnFlag,
		evtTopicFlag,
		evtChangesFlag,
		evtUninstallFlag,
		evtLogsFlag,
		evtObjectFlag,
	}
	// `evt` action
	evtAction = func(c *Context) error {
		return nil
	}
	// `evt` command
	evtCommand = Command{
		Name: "event", Aliases: []string{"evt"}, Usage: "New/polling/uninstall a filter object",
		Action: evtAction,
		Flags:  evtFlags}
)

func migrateFlags(a func(c *Context) error) func(*Context) error {
	return func(c *Context) error {
		for _, n := range c.FlagNames() {
			if c.IsSet(n) {
				c.GlobalSet(n, c.String(n))
			}
		}
		return a(c)
	}
}

func main() {
	app := NewApp()
	app.Usage = "DrvLot Command Line Interface"
	app.Version = "1.0.0"
	app.Commands = []Command{
		apiCommand,
		accCommand,
		ftoCommand,
		accountsCommand,
		miscCommand,
		bigCommand,
		hexCommand,
		shaCommand,
		signCommand,
		codeCommand,
		storageCommand,
		balanceCommand,
		blkCommand,
		txnCommand,
		evtCommand,
	}
	app.Flags = append(app.Flags, hexFlags...)
	app.Run(os.Args)
}
