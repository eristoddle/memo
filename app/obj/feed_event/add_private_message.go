package feed_event

import (
	"github.com/jchavannes/jgo/jerr"
	"github.com/memocash/memo/app/db"
)

func AddPrivateMessage(privateMessage *db.MemoPrivateMessage) error {
	var feed = db.FeedEvent{
		PkHash: privateMessage.PkHash,
		TxHash: privateMessage.TxHash,
	}
	if privateMessage.Block != nil {
		feed.BlockHeight = privateMessage.Block.Height
	}
	err := feed.Save()
	if err != nil {
		return jerr.Get("error saving feed privateMessage", err)
	}
	return nil
}
