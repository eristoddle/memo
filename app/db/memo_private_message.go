package db

import (
	"fmt"
	"html"
	"time"

	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/jchavannes/jgo/jerr"
	"github.com/memocash/memo/app/bitcoin/script"
	"github.com/memocash/memo/app/bitcoin/wallet"
)

type MemoPrivateMessage struct {
	Id         uint   `gorm:"primary_key"`
	TxHash     []byte `gorm:"unique;size:50"`
	ParentHash []byte
	PkHash     []byte `gorm:"index:pk_hash"`
	PkScript   []byte `gorm:"size:500"`
	Address    string
	// Generic Above
	ParentTxHash []byte `gorm:"index:parent_tx_hash"`
	Parent       *MemoPrivateMessage
	RootTxHash   []byte `gorm:"index:root_tx_hash"`
	Message      string `gorm:"size:500"`
	Count        int    `gorm:"count"`
	Link         []byte `gorm:"index:last_tx_hash"`
	// Generic Below
	BlockId   uint
	Block     *Block
	CreatedAt time.Time
	UpdatedAt time.Time
}

func (m *MemoPrivateMessage) Save() error {
	result := save(&m)
	if result.Error != nil {
		return jerr.Get("error saving memo private message", result.Error)
	}
	return nil
}

func (m MemoPrivateMessage) GetTransactionHashString() string {
	hash, err := chainhash.NewHash(m.TxHash)
	if err != nil {
		jerr.Get("error getting chainhash from memo private message", err).Print()
		return ""
	}
	return hash.String()
}

func (m MemoPrivateMessage) GetParentTransactionHashString() string {
	hash, err := chainhash.NewHash(m.ParentTxHash)
	if err != nil {
		jerr.Get("error getting chainhash from memo private message", err).Print()
		return ""
	}
	return hash.String()
}

func (m MemoPrivateMessage) GetRootTransactionHashString() string {
	hash, err := chainhash.NewHash(m.RootTxHash)
	if err != nil {
		jerr.Get("error getting chainhash from memo private message", err).Print()
		return ""
	}
	return hash.String()
}

func (m MemoPrivateMessage) GetAddressString() string {
	return m.GetAddress().GetEncoded()
}

func (m MemoPrivateMessage) GetAddress() wallet.Address {
	return wallet.GetAddressFromPkHash(m.PkHash)
}

func (m MemoPrivateMessage) GetScriptString() string {
	return html.EscapeString(script.GetScriptString(m.PkScript))
}

func (m MemoPrivateMessage) GetMessage() string {
	return m.Message
}

func (m MemoPrivateMessage) GetTimeString() string {
	if m.BlockId != 0 {
		if m.Block != nil {
			return m.Block.Timestamp.Format("2006-01-02 15:04:05")
		} else {
			return "Unknown"
		}
	}
	return "Unconfirmed"
}

func GetMemoPrivateMessage(txHash []byte) (*MemoPrivateMessage, error) {
	var memoPrivateMessage MemoPrivateMessage
	err := findPreloadColumns([]string{
		BlockTable,
	}, &memoPrivateMessage, MemoPrivateMessage{
		TxHash: txHash,
	})
	if err != nil {
		return nil, jerr.Get("error getting memo private message", err)
	}
	return &memoPrivateMessage, nil
}

func GetPrivateMessagesByTxHashes(txHashes [][]byte) ([]*MemoPrivateMessage, error) {
	var memoPrivateMessages []*MemoPrivateMessage
	db, err := getDb()
	if err != nil {
		return nil, jerr.Get("error getting db", err)
	}
	result := db.
		Preload(BlockTable).
		Where("tx_hash IN (?)", txHashes).
		Find(&memoPrivateMessages)
	if result.Error != nil {
		return nil, jerr.Get("error getting memo private messages", result.Error)
	}
	return memoPrivateMessages, nil
}

func GetMemoPrivateMessageById(id uint) (*MemoPrivateMessage, error) {
	var memoPrivateMessage MemoPrivateMessage
	err := find(&memoPrivateMessage, MemoPrivateMessage{
		Id: id,
	})
	if err != nil {
		return nil, jerr.Get("error getting memo post", err)
	}
	return &memoPrivateMessage, nil
}

func GetPrivateMessagesForPkHash(pkHash []byte, offset uint) ([]*MemoPrivateMessage, error) {
	if len(pkHash) == 0 {
		return nil, nil
	}
	var memoPrivateMessages []*MemoPrivateMessage
	db, err := getDb()
	if err != nil {
		return nil, jerr.Get("error getting db", err)
	}
	query := db.
		Preload(BlockTable).
		Order("id DESC").
		Limit(25).
		Offset(offset)
	result := query.Find(&memoPrivateMessages, &MemoPrivateMessage{
		PkHash: pkHash,
	})
	if result.Error != nil {
		return nil, jerr.Get("error getting memo private messages", result.Error)
	}
	return memoPrivateMessages, nil
}

func GetRecentPrivateMessages(offset uint, searchString string) ([]*MemoPrivateMessage, error) {
	db, err := getDb()
	if err != nil {
		return nil, jerr.Get("error getting db", err)
	}
	db = db.Preload(BlockTable)
	if searchString != "" {
		db = db.Where("message LIKE ?", fmt.Sprintf("%%%s%%", searchString))
	}
	var memoPrivateMessages []*MemoPrivateMessage
	result := db.
		Limit(25).
		Offset(offset).
		Order("id DESC").
		Find(&memoPrivateMessages)
	if result.Error != nil {
		return nil, jerr.Get("error running query", result.Error)
	}
	return memoPrivateMessages, nil
}

func GetPrivateMessages(offset uint) ([]*MemoPrivateMessage, error) {
	db, err := getDb()
	if err != nil {
		return nil, jerr.Get("error getting db", err)
	}
	var memoPrivateMessages []*MemoPrivateMessage
	result := db.
		Preload(BlockTable).
		Limit(25).
		Offset(offset).
		Order("id ASC").
		Find(&memoPrivateMessages)
	if result.Error != nil {
		return nil, jerr.Get("error running query", result.Error)
	}
	return memoPrivateMessages, nil
}
