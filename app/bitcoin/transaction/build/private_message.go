package build

import (
	"sort"

	"github.com/jchavannes/jgo/jerr"
	"github.com/memocash/memo/app/bitcoin/memo"
	"github.com/memocash/memo/app/bitcoin/wallet"
	"github.com/memocash/memo/app/db"
	"github.com/memocash/memo/app/util"
)

const (
	firstChunkSize = memo.MaxPostSize - 2
	chunkSize      = memo.MaxPrivateMessageSizeChunk
)

func chunkMessage(runes []rune) []string {
	var chunks []string
	for i := 0; i < len(runes); i += chunkSize {
		nn := i + chunkSize
		if nn > len(runes) {
			nn = len(runes)
		}
		chunks = append(chunks, string(runes[i:nn]))
	}
	return chunks
}

// TransactionCount : Get count of transactions to send encrypted message
func TransactionCount(message string, address string, privateKey *wallet.PrivateKey) (int, error) {
	hexPk := privateKey.GetHex()
	privateMessage, err := util.EncryptPM(address, hexPk, message)
	if err != nil {
		return 0, jerr.Get("error encrypting private message", err)
	}
	runes := []rune(privateMessage)
	chain := chunkMessage(runes[firstChunkSize:])
	return len(chain) + 1, nil
}

// PrivateMessage : Build private message transaction
func PrivateMessage(message string, privateKey *wallet.PrivateKey, pubKey string, messageAddress wallet.Address) ([]*memo.Tx, error) {
	hexPk := privateKey.GetHex()
	privateMessage, err := util.EncryptPM(pubKey, hexPk, message)
	if err != nil {
		return nil, jerr.Get("error encrypting private message", err)
	}
	runes := []rune(privateMessage)
	start := string(runes[0:firstChunkSize])
	chain := chunkMessage(runes[firstChunkSize:])

	spendableTxOuts, err := db.GetSpendableTransactionOutputsForPkHash(privateKey.GetPublicKey().GetAddress().GetScriptAddress())
	if err != nil {
		return nil, jerr.Get("error getting spendable tx outs", err)
	}
	sort.Sort(db.TxOutSortByValue(spendableTxOuts))

	var txns []*memo.Tx
	memoTx, spendableTxOuts, err := buildWithTxOutsAndRecipient([]memo.Output{{
		Type:    memo.OutputTypeMemoPrivateMessage,
		Data:    []byte(start),
		RefData: []byte(string(len(chain))),
	}}, spendableTxOuts, privateKey, messageAddress)
	if err != nil {
		return nil, jerr.Get("error creating tx", err)
	}
	txns = append(txns, memoTx)

	lastTxHash := memoTx.MsgTx.TxHash()
	lastTxHashBytes := lastTxHash.CloneBytes()
	for _, chunk := range chain {
		memoTx, spendableTxOuts, err = buildWithTxOuts([]memo.Output{{
			Type:    memo.OutputTypeMemoPrivateMessage,
			Data:    []byte(chunk),
			RefData: []byte(lastTxHashBytes),
		}}, spendableTxOuts, privateKey)
		if err != nil {
			return nil, jerr.Get("error creating tx", err)
		}
		lastTxHash := memoTx.MsgTx.TxHash()
		lastTxHashBytes = lastTxHash.CloneBytes()
		txns = append(txns, memoTx)
	}

	return txns, nil
}
