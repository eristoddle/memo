package build

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/btcsuite/btcd/btcec"
	"github.com/jchavannes/jgo/jerr"
	"github.com/memocash/memo/app/bitcoin/memo"
	"github.com/memocash/memo/app/bitcoin/wallet"
	"github.com/memocash/memo/app/db"
)

// Transactions : Struct for bch transactions call
type Transactions struct {
	Data struct {
		TotalCount int64 `json:"total_count"`
		Page       int64 `json:"page"`
		PageSize   int64 `json:"page_size"`
		List       []struct {
			Hash string `json:"hash"`
		} `json:"list"`
	} `json:"data"`
}

// Transaction : Struct for bch transaction call
type Transaction struct {
	ErrorNo int64 `json:"error_no"`
	Data    struct {
		Inputs []struct {
			PrevAddresses []string `json:"prev_addresses"`
			ScriptAsm     string   `json:"script_asm"`
		} `json:"inputs"`
	} `json:"data"`
}

const (
	throttle  int = 210
	keyLength int = 66
)

var (
	ciphCurveBytes  = [2]byte{0x02, 0xCA}
	ciphCoordLength = [2]byte{0x00, 0x20}

	errUnsupportedCurve = errors.New("unsupported curve")
	errInvalidXLength   = errors.New("invalid X length, must be 32")
	errInvalidYLength   = errors.New("invalid Y length, must be 32")
	errInvalidPadding   = errors.New("invalid PKCS#7 padding")
	errInputTooShort    = errors.New("ciphertext too short")
	errInvalidMAC       = errors.New("invalid mac hash")
	errNoTransactions   = errors.New("no public key available, no transactions for address")
)

func makeRequest(url string) ([]byte, error) {
	var client http.Client
	resp, err := client.Get(url)

	if err != nil {
		return []byte(""), err
	}

	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	return body, nil
}

func getPubkey(hash string, address string) (string, error) {
	var pubkey string
	var record Transaction
	safeHash := url.QueryEscape(hash)
	url := fmt.Sprintf("https://bch-chain.api.btc.com/v3/tx/%s?verbose=3", safeHash)

	body, err := makeRequest(url)
	if err != nil {
		return "", err
	}

	err = json.Unmarshal(body, &record)
	if err != nil {
		return "", err
	}

	for _, i := range record.Data.Inputs {
		for _, a := range i.PrevAddresses {
			if a == address {
				parts := strings.Fields(i.ScriptAsm)
				pubkey = parts[len(parts)-1]
				if len(pubkey) == keyLength {
					return pubkey, nil
				}
			}
		}
	}
	return pubkey, nil
}

// TODO: Replace all of this by querying users transactions, also a boolean on message button
func harvestKey(address string) (string, error) {
	var pubkey string
	var record Transactions
	safeAddress := url.QueryEscape(address)
	url := fmt.Sprintf("https://bch-chain.api.btc.com/v3/address/%s/tx", safeAddress)

	body, err := makeRequest(url)
	if err != nil {
		return "", err
	}

	err = json.Unmarshal(body, &record)
	if err != nil {
		return "", err
	}

	for _, t := range record.Data.List {
		time.Sleep(time.Millisecond * time.Duration(throttle))
		pubkey, err := getPubkey(t.Hash, address)
		if err != nil {
			return "", err
		}
		if len(pubkey) == keyLength {
			return pubkey, nil
		}
	}

	if len(pubkey) != keyLength {
		return "", errNoTransactions
	}
	return pubkey, nil
}

func addPKCSPadding(src []byte) []byte {
	padding := aes.BlockSize - len(src)%aes.BlockSize
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(src, padtext...)
}

func removePKCSPadding(src []byte) ([]byte, error) {
	length := len(src)
	padLength := int(src[length-1])
	if padLength > aes.BlockSize || length < aes.BlockSize {
		return nil, errInvalidPadding
	}

	return src[:length-padLength], nil
}

func chunkMessage(message string) []string {
	log.Print("total private message length: ", len(message))
	var chunks []string
	runes := []rune(message)
	chunkSize := memo.MaxPostSize - 1

	for i := 0; i < len(runes); i += chunkSize {
		nn := i + chunkSize
		if nn > len(runes) {
			nn = len(runes)
		}
		chunks = append(chunks, string(runes[i:nn]))
		chunkSize = memo.MaxPrivateMessageSizeChunk
	}
	return chunks
}

// Encrypt : Encrypt message using sender hex private key and recipient legacy address
func Encrypt(recipientAddress string, senderPrivate string, in string) (string, error) {
	hexPubKey, err := harvestKey(recipientAddress)
	if err != nil {
		return "", err
	}

	privateBytes, err := hex.DecodeString(senderPrivate)
	if err != nil {
		return "", err
	}

	privKey, _ := btcec.PrivKeyFromBytes(btcec.S256(), privateBytes)

	publicBytes, err := hex.DecodeString(hexPubKey)
	if err != nil {
		return "", err
	}

	pubKey, err := btcec.ParsePubKey(publicBytes, btcec.S256())
	if err != nil {
		return "", err
	}

	secret := btcec.GenerateSharedSecret(privKey, pubKey)
	derivedKey := sha512.Sum512(secret)
	keyE := derivedKey[:32]
	keyM := derivedKey[32:]

	paddedIn := addPKCSPadding([]byte(in))
	out := make([]byte, aes.BlockSize+70+len(paddedIn)+sha256.Size)
	iv := out[:aes.BlockSize]
	if _, err = io.ReadFull(rand.Reader, iv); err != nil {
		return "", err
	}

	pb := pubKey.SerializeUncompressed()
	offset := aes.BlockSize

	copy(out[offset:offset+4], append(ciphCurveBytes[:], ciphCoordLength[:]...))
	offset += 4
	copy(out[offset:offset+32], pb[1:33])
	offset += 32
	copy(out[offset:offset+2], ciphCoordLength[:])
	offset += 2
	copy(out[offset:offset+32], pb[33:])
	offset += 32

	block, err := aes.NewCipher(keyE)
	if err != nil {
		return "", err
	}
	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(out[offset:len(out)-sha256.Size], paddedIn)

	hm := hmac.New(sha256.New, keyM)
	hm.Write(out[:len(out)-sha256.Size])
	copy(out[len(out)-sha256.Size:], hm.Sum(nil))

	return hex.EncodeToString(out), nil
}

// Decrypt : Decrypt message using sender legacy address and recipient hex private key
func Decrypt(senderAddress string, recipientPrivate string, ciphertext string) (string, error) {
	hexPubKey, err := harvestKey(senderAddress)
	if err != nil {
		return "", err
	}

	privateBytes, err := hex.DecodeString(recipientPrivate)
	if err != nil {
		return "", err
	}

	privKey, _ := btcec.PrivKeyFromBytes(btcec.S256(), privateBytes)

	publicBytes, err := hex.DecodeString(hexPubKey)
	if err != nil {
		return "", err
	}

	pubKey, err := btcec.ParsePubKey(publicBytes, btcec.S256())
	if err != nil {
		return "", err
	}

	in, err := hex.DecodeString(ciphertext)
	if err != nil {
		return "", err
	}

	if len(in) < aes.BlockSize+70+aes.BlockSize+sha256.Size {
		return "", errInputTooShort
	}

	iv := in[:aes.BlockSize]
	offset := aes.BlockSize

	if !bytes.Equal(in[offset:offset+2], ciphCurveBytes[:]) {
		return "", errUnsupportedCurve
	}
	offset += 2

	if !bytes.Equal(in[offset:offset+2], ciphCoordLength[:]) {
		return "", errInvalidXLength
	}
	offset += 34

	if !bytes.Equal(in[offset:offset+2], ciphCoordLength[:]) {
		return "", errInvalidYLength
	}
	offset += 34

	if (len(in)-aes.BlockSize-offset-sha256.Size)%aes.BlockSize != 0 {
		return "", errInvalidPadding
	}

	messageMAC := in[len(in)-sha256.Size:]

	ecdhKey := btcec.GenerateSharedSecret(privKey, pubKey)
	derivedKey := sha512.Sum512(ecdhKey)
	keyE := derivedKey[:32]
	keyM := derivedKey[32:]

	hm := hmac.New(sha256.New, keyM)
	hm.Write(in[:len(in)-sha256.Size])
	expectedMAC := hm.Sum(nil)
	if !hmac.Equal(messageMAC, expectedMAC) {
		return "", errInvalidMAC
	}

	block, err := aes.NewCipher(keyE)
	if err != nil {
		return "", err
	}
	mode := cipher.NewCBCDecrypter(block, iv)
	plaintext := make([]byte, len(in)-offset-sha256.Size)
	mode.CryptBlocks(plaintext, in[offset:len(in)-sha256.Size])

	out, err := removePKCSPadding(plaintext)
	if err != nil {
		return "", err
	}

	return string(out), nil
}

// TransactionCount : Get count of transactions to send encrypted message
func TransactionCount(message string, address string, privateKey *wallet.PrivateKey) (int, error) {
	hexPk := privateKey.GetHex()
	privateMessage, err := Encrypt(address, hexPk, message)
	if err != nil {
		return 0, jerr.Get("error encrypting private message", err)
	}
	chunkedMessage := chunkMessage(privateMessage)
	return len(chunkedMessage), nil
}

// AssembleMessage : Concat outputs from a message transaction and decrypt
// TODO: Implement message chaining for long messages
func AssembleMessage(message string) (string, error) {
	return "", nil
}

// PrivateMessage : Build private message transaction
func PrivateMessage(message string, address string, privateKey *wallet.PrivateKey) ([]*memo.Tx, error) {
	hexPk := privateKey.GetHex()
	privateMessage, err := Encrypt(address, hexPk, message)
	if err != nil {
		return nil, jerr.Get("error encrypting private message", err)
	}

	spendableTxOuts, err := db.GetSpendableTransactionOutputsForPkHash(privateKey.GetPublicKey().GetAddress().GetScriptAddress())
	if err != nil {
		return nil, jerr.Get("error getting spendable tx outs", err)
	}
	sort.Sort(db.TxOutSortByValue(spendableTxOuts))

	var txns []*memo.Tx
	chunks := chunkMessage(privateMessage)
	start := chunks[0]
	chain := chunks[1:]

	memoTx, spendableTxOuts, err := buildWithTxOuts([]memo.Output{{
		Type:    memo.OutputTypeMemoPrivateMessage,
		Data:    []byte(start),
		RefData: []byte(string(len(chain))),
	}}, spendableTxOuts, privateKey)
	if err != nil {
		return nil, jerr.Get("error creating tx", err)
	}
	txns = append(txns, memoTx)

	lastTxHash := memoTx.MsgTx.TxHash()
	lastTxHashBytes := lastTxHash.CloneBytes()

	for _, chunk := range chain {
		memoTx, spendableTxOuts, err := buildWithTxOuts([]memo.Output{{
			Type:    memo.OutputTypeMemoPrivateMessage,
			Data:    []byte(chunk),
			RefData: []byte(lastTxHashBytes),
		}}, spendableTxOuts, privateKey)
		if err != nil {
			log.Print("spendableTxOuts: ", spendableTxOuts)
			return nil, jerr.Get("error creating tx", err)
		}
		lastTxHash := memoTx.MsgTx.TxHash()
		lastTxHashBytes = lastTxHash.CloneBytes()
		txns = append(txns, memoTx)
	}

	return txns, nil
}
