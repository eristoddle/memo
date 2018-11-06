package build

import (
	"log"
	"sort"

	"github.com/jchavannes/jgo/jerr"
	"github.com/memocash/memo/app/bitcoin/memo"
	"github.com/memocash/memo/app/bitcoin/wallet"
	"github.com/memocash/memo/app/db"
	"github.com/memocash/memo/app/util"
)

func chunkMessage(runes []rune) []string {
	var chunks []string
	chunkSize := memo.MaxPrivateMessageSizeChunk
	for i := 0; i < len(runes); i += chunkSize {
		nn := i + chunkSize
		if nn > len(runes) {
			nn = len(runes)
		}
		chunks = append(chunks, string(runes[i:nn]))
	}
	return chunks
}

// PrivateMessage : Build private message transaction
func PrivateMessage(message string, privateKey *wallet.PrivateKey, pubKey string) ([]*memo.Tx, error) {
	hexPk := privateKey.GetHex()
	privateMessage, err := util.EncryptPM(pubKey, hexPk, message)

	// TODO: Remove logs
	log.Print("original: ", message)
	log.Print("encrypted: ", privateMessage)

	runes := []rune(privateMessage)
	firstChunkSize := memo.MaxPostSize - 2
	start := string(runes[0:firstChunkSize])
	chain := chunkMessage(runes[firstChunkSize:])

	// TODO: Remove logs
	log.Print("start: ", start)

	spendableTxOuts, err := db.GetSpendableTransactionOutputsForPkHash(privateKey.GetPublicKey().GetAddress().GetScriptAddress())
	if err != nil {
		return nil, jerr.Get("error getting spendable tx outs", err)
	}
	sort.Sort(db.TxOutSortByValue(spendableTxOuts))

	var txns []*memo.Tx
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
	// TODO: This only works for less than 3 transactions, 3rd gets created never makes it to blockchain
	for _, chunk := range chain {
		// TODO: Remove logs
		log.Print("chain: ", chunk)
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
