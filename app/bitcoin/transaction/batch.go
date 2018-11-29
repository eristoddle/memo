package transaction

import (
	"github.com/jchavannes/jgo/jerr"
	"github.com/memocash/memo/app/cache"
	"github.com/memocash/memo/app/db"
	"github.com/memocash/memo/app/notify"
)

var (
	batchPostProcessing  bool
	followsToNotify      []*db.MemoFollow
	likesToNotify        []*db.MemoLike
	repliesToNotify      []*db.MemoPost
	rootTxHashesToUpdate []*db.MemoPost
	messagesToNotify     []*db.MemoPrivateMessage
)

func EnableBatchPostProcessing() {
	batchPostProcessing = true
}

func DisableBatchPostProcessing() {
	batchPostProcessing = false
}

func ProcessNotifications() (uint, []error) {
	var numNotifications uint
	var errors []error
	for _, memoFollow := range followsToNotify {
		err := notify.AddNewFollowerNotification(memoFollow, true)
		if err != nil {
			errors = append(errors, jerr.Get("error adding new follower notification", err))
		}
		numNotifications++
	}
	followsToNotify = []*db.MemoFollow{}
	for _, memoLike := range likesToNotify {
		err := notify.AddLikeNotification(memoLike, true)
		if err != nil {
			errors = append(errors, jerr.Get("error adding like notification", err))
		}
		numNotifications++
	}
	likesToNotify = []*db.MemoLike{}
	for _, memoPost := range repliesToNotify {
		err := notify.AddReplyNotification(memoPost, true)
		if err != nil {
			errors = append(errors, jerr.Get("error adding reply notification", err))
		}
		numNotifications++
	}
	repliesToNotify = []*db.MemoPost{}
	return numNotifications, errors
}

func UpdateRootTxHashes() (uint, []error) {
	var numRootTxHashesUpdated uint
	var errors []error
	for _, memoPost := range rootTxHashesToUpdate {
		err := doUpdateRootTxHash(memoPost)
		if err != nil {
			errors = append(errors, jerr.Get("error updating root tx hash", err))
		}
		numRootTxHashesUpdated++
	}
	rootTxHashesToUpdate = []*db.MemoPost{}
	return numRootTxHashesUpdated, errors
}

func addFollowNotification(memoFollow *db.MemoFollow) {
	if batchPostProcessing {
		followsToNotify = append(followsToNotify, memoFollow)
		return
	}
	err := notify.AddNewFollowerNotification(memoFollow, true)
	if err != nil {
		jerr.Get("error adding new follower notification", err).Print()
	}
}

func addLikeNotification(memoLike *db.MemoLike) {
	if batchPostProcessing {
		likesToNotify = append(likesToNotify, memoLike)
		return
	}
	err := notify.AddLikeNotification(memoLike, true)
	if err != nil {
		jerr.Get("error adding like notification", err).Print()
	}
}

func addReplyNotification(memoPost *db.MemoPost) {
	if batchPostProcessing {
		repliesToNotify = append(repliesToNotify, memoPost)
		return
	}
	err := notify.AddReplyNotification(memoPost, true)
	if err != nil {
		jerr.Get("error adding reply notification", err).Print()
	}
}

func addPrivateMessageNotification(memoPrivateMessage *db.MemoPrivateMessage) {
	err := cache.BatchSetUnreadMessageCount(memoPrivateMessage)
	if err != nil {
		jerr.Get("error adding private message notification", err).Print()
	}
}

func updateRootTxHash(memoPost *db.MemoPost) {
	if batchPostProcessing {
		rootTxHashesToUpdate = append(rootTxHashesToUpdate, memoPost)
		return
	}
	err := doUpdateRootTxHash(memoPost)
	if err != nil {
		jerr.Get("error updating root tx hash", err).Print()
	}
}

func doUpdateRootTxHash(memoPost *db.MemoPost) error {
	var parentTxHash = memoPost.ParentTxHash
	for {
		prevMemoPost, err := db.GetMemoPost(parentTxHash)
		if err != nil {
			return jerr.Get("error getting reply post from db", err)
		}
		if len(prevMemoPost.ParentTxHash) == 0 {
			memoPost.RootTxHash = prevMemoPost.TxHash
			break
		} else if len(prevMemoPost.RootTxHash) > 0 {
			memoPost.RootTxHash = prevMemoPost.RootTxHash
			break
		}
		parentTxHash = prevMemoPost.ParentTxHash
	}
	err := memoPost.Save()
	if err != nil {
		return jerr.Get("error saving memo post", err)
	}
	return nil
}
