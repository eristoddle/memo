package db

import (
	"time"

	"github.com/jchavannes/btcd/chaincfg/chainhash"
	"github.com/jchavannes/jgo/jerr"
	"github.com/memocash/memo/app/bitcoin/wallet"
)

type FeedEventType int

const (
	FeedEventPost           FeedEventType = 1
	FeedEventReply          FeedEventType = 2
	FeedEventLike           FeedEventType = 3
	FeedEventTopicPost      FeedEventType = 4
	FeedEventCreatePoll     FeedEventType = 5
	FeedEventPollVote       FeedEventType = 6
	FeedEventSetName        FeedEventType = 7
	FeedEventSetProfile     FeedEventType = 8
	FeedEventSetProfilePic  FeedEventType = 9
	FeedEventFollowUser     FeedEventType = 10
	FeedEventFollowTopic    FeedEventType = 11
	FeedEventPrivateMessage FeedEventType = 12
)

var PostEvents = []FeedEventType{
	FeedEventPost,
	FeedEventReply,
	FeedEventTopicPost,
	FeedEventCreatePoll,
}

type FeedEvent struct {
	Id          uint   `gorm:"primary_key"`
	Block       *Block `gorm:"foreignkey:BlockHeight"`
	BlockHeight uint   `gorm:"index:block_height"`
	PkHash      []byte `gorm:"index:pk_hash"`
	TxHash      []byte `gorm:"unique"`
	EventType   FeedEventType
	CreatedAt   time.Time
	UpdatedAt   time.Time
}

func (f *FeedEvent) Save() error {
	result := save(&f)
	if result.Error == nil {
		return nil
	} else if !IsDuplicateEntryError(result.Error) {
		return jerr.Get("error saving feed event", result.Error)
	}
	if f.BlockHeight == 0 {
		return nil
	}
	feed, err := GetFeedByTxHash(f.TxHash)
	if err != nil {
		return jerr.Get("error getting feed event", err)
	}
	if feed.BlockHeight != 0 {
		return nil
	}
	feed.BlockHeight = f.BlockHeight
	result = save(&feed)
	if result.Error != nil {
		return jerr.Get("error updating feed event", result.Error)
	}
	return nil
}

func (f FeedEvent) GetAddress() wallet.Address {
	return wallet.GetAddressFromPkHash(f.PkHash)
}

func (f FeedEvent) GetTransactionHashString() string {
	hash, err := chainhash.NewHash(f.TxHash)
	if err != nil {
		jerr.Get("error getting chainhash from feed event", err).Print()
		return ""
	}
	return hash.String()
}

func GetRecentFeedForPkHash(pkHash []byte, offset uint) ([]*FeedEvent, error) {
	var feedEvents []*FeedEvent
	db, err := getDb()
	if err != nil {
		return nil, jerr.Get("error getting db", err)
	}
	joinSelect := "SELECT " +
		"	follow_pk_hash " +
		"FROM memo_follows " +
		"JOIN (" +
		"	SELECT MAX(id) AS id" +
		"	FROM memo_follows" +
		"	WHERE pk_hash = ?" +
		"	GROUP BY pk_hash, follow_pk_hash" +
		") sq ON (sq.id = memo_follows.id) " +
		"WHERE unfollow = 0 "
	result := db.
		Limit(25).
		Preload(BlockTable).
		Offset(offset).
		Joins("JOIN ("+joinSelect+") fsq ON (feed_events.pk_hash = fsq.follow_pk_hash)", pkHash).
		Order("block_height != 0, block_height DESC, id DESC").
		Find(&feedEvents)
	if result.Error != nil {
		return nil, jerr.Get("error getting feed events", result.Error)
	}
	return feedEvents, nil
}

func GetRecentFeedEvents(offset uint) ([]*FeedEvent, error) {
	var feedEvents []*FeedEvent
	db, err := getDb()
	if err != nil {
		return nil, jerr.Get("error getting db", err)
	}
	result := db.
		Limit(25).
		Preload(BlockTable).
		Offset(offset).
		Order("block_height != 0, block_height DESC, id DESC").
		Find(&feedEvents)
	if result.Error != nil {
		return nil, jerr.Get("error getting feed events", result.Error)
	}
	return feedEvents, nil
}

func GetRecentFeedUserEvents(pkHash []byte, offset uint, eventTypes []FeedEventType) ([]*FeedEvent, error) {
	var feedEvents []*FeedEvent
	db, err := getDb()
	if err != nil {
		return nil, jerr.Get("error getting db", err)
	}
	query := db.
		Limit(25).
		Preload(BlockTable).
		Where("pk_hash = ?", pkHash).
		Offset(offset).
		Order("block_height != 0, block_height DESC, id DESC")
	if eventTypes != nil {
		query = query.Where("event_type IN (?)", eventTypes)
	}
	result := query.Find(&feedEvents)
	if result.Error != nil {
		return nil, jerr.Get("error getting feed events", result.Error)
	}
	return feedEvents, nil
}

func GetFeedByTxHash(txHash []byte) (*FeedEvent, error) {
	var feed FeedEvent
	err := find(&feed, FeedEvent{
		TxHash: txHash,
	})
	if err != nil {
		return nil, jerr.Get("error getting feed item", err)
	}
	return &feed, nil
}
