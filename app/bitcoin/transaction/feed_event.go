package transaction

import (
	"github.com/jchavannes/jgo/jerr"
	"github.com/memocash/memo/app/db"
	"github.com/memocash/memo/app/obj/feed_event"
)

func addMemoPostFeedEvent(memoPost *db.MemoPost) {
	go func() {
		err := feed_event.AddPost(memoPost)
		if err != nil {
			jerr.Get("error adding post feed event", err).Print()
		}
	}()
}

func addMemoPrivateMessageFeedEvent(memoPrivateMessage *db.MemoPrivateMessage) {
	go func() {
		err := feed_event.AddPrivateMessage(memoPrivateMessage)
		if err != nil {
			jerr.Get("error adding private message feed event", err).Print()
		}
	}()
}

func addMemoSetNameFeedEvent(memoSetName *db.MemoSetName) {
	go func() {
		err := feed_event.AddSetName(memoSetName)
		if err != nil {
			jerr.Get("error adding set name feed event", err).Print()
		}
	}()
}

func addMemoSetProfilePicFeedEvent(memoSetPic *db.MemoSetPic) {
	go func() {
		err := feed_event.AddSetProfilePic(memoSetPic)
		if err != nil {
			jerr.Get("error adding set pic feed event", err).Print()
		}
	}()
}

func addMemoFollowFeedEvent(memoFollow *db.MemoFollow) {
	go func() {
		err := feed_event.AddFollow(memoFollow)
		if err != nil {
			jerr.Get("error adding follow feed event", err).Print()
		}
	}()
}

func addMemoLikeFeedEvent(memoLike *db.MemoLike) {
	go func() {
		err := feed_event.AddLike(memoLike)
		if err != nil {
			jerr.Get("error adding like feed event", err).Print()
		}
	}()
}

func addMemoTopicFollowFeedEvent(memoFollowTopic *db.MemoTopicFollow) {
	go func() {
		err := feed_event.AddTopicFollow(memoFollowTopic)
		if err != nil {
			jerr.Get("error adding topic follow feed event", err).Print()
		}
	}()
}

func addMemoSetProfileFeedEvent(memoSetProfile *db.MemoSetProfile) {
	go func() {
		err := feed_event.AddSetProfile(memoSetProfile)
		if err != nil {
			jerr.Get("error adding set profile feed event", err).Print()
		}
	}()
}

func addMemoPollVoteFeedEvent(memoPollVote *db.MemoPollVote) {
	go func() {
		err := feed_event.AddPollVote(memoPollVote)
		if err != nil {
			jerr.Get("error adding poll vote feed event", err).Print()
		}
	}()
}
