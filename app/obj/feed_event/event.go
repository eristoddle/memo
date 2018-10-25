package feed_event

import (
	"net/url"
	"strings"

	"github.com/memocash/memo/app/bitcoin/wallet"
	"github.com/memocash/memo/app/db"
	"github.com/memocash/memo/app/obj/rep"
	"github.com/memocash/memo/app/profile"
	"github.com/memocash/memo/app/util"
	"github.com/memocash/memo/app/util/format"
)

type Event struct {
	FeedEvent        *db.FeedEvent
	Name             string
	SelfPkHash       []byte
	ProfilePic       *db.MemoSetPic
	Post             *profile.Post
	PrivateMessage   *db.MemoPrivateMessage
	MemoLike         *db.MemoLike
	PollOption       *db.MemoPollOption
	PollVote         *db.MemoPollVote
	SetName          *db.MemoSetName
	SetProfile       *db.MemoSetProfile
	SetProfilePic    *db.MemoSetPic
	UserFollow       *db.MemoFollow
	FollowName       string
	FollowProfilePic *db.MemoSetPic
	TopicFollow      *db.MemoTopicFollow
	Reputation       *rep.Reputation
	FollowReputation *rep.Reputation
	ShowMedia        bool
}

func (e *Event) TimeAgo() string {
	if e.FeedEvent.Block != nil && e.FeedEvent.Block.Timestamp.Before(e.FeedEvent.CreatedAt) {
		return util.GetTimeAgo(e.FeedEvent.Block.Timestamp)
	}
	return util.GetTimeAgo(e.FeedEvent.CreatedAt)
}

func (e *Event) GetAddressString() string {
	return e.FeedEvent.GetAddress().GetEncoded()
}

func (e *Event) GetFollowName() string {
	if e.FollowName == "" {
		return e.FeedEvent.GetAddress().GetEncoded()
	}
	return e.FollowName
}

func (e *Event) GetFollowAddressString() string {
	if e.UserFollow == nil {
		return ""
	}
	address := wallet.GetAddressFromPkHash(e.UserFollow.FollowPkHash)
	return address.GetEncoded()
}

func (e *Event) GetProfileText() string {
	if e.SetProfile == nil {
		return ""
	}
	var profileText = e.SetProfile.Profile
	profileText = strings.TrimSpace(profileText)
	profileText = format.AddLinks(profileText)
	return profileText
}

func (e *Event) GetSetName() string {
	if e.SetName == nil {
		return ""
	}
	return e.SetName.Name
}

func (e *Event) GetProfilePicMessage() string {
	var msg = e.SetProfilePic.Url
	if e.ShowMedia {
		msg = format.AddImgurImages(msg)
	}
	msg = strings.TrimSpace(msg)
	return msg
}

func (e *Event) GetTopicUrl() string {
	if e.TopicFollow == nil {
		return ""
	}
	return url.QueryEscape(e.TopicFollow.Topic)
}

func (e *Event) IsLike() bool {
	return e.FeedEvent.EventType == db.FeedEventLike
}

func (e *Event) IsPost() bool {
	return e.FeedEvent.EventType == db.FeedEventPost
}

func (e *Event) IsPrivateMessage() bool {
	return e.FeedEvent.EventType == db.FeedEventPrivateMessage
}

func (e *Event) IsReply() bool {
	return e.FeedEvent.EventType == db.FeedEventReply
}

func (e *Event) IsTopicPost() bool {
	return e.FeedEvent.EventType == db.FeedEventTopicPost
}

func (e *Event) IsCreatePoll() bool {
	return e.FeedEvent.EventType == db.FeedEventCreatePoll
}

func (e *Event) IsPollVote() bool {
	return e.FeedEvent.EventType == db.FeedEventPollVote
}

func (e *Event) IsSetName() bool {
	return e.FeedEvent.EventType == db.FeedEventSetName
}

func (e *Event) IsSetProfile() bool {
	return e.FeedEvent.EventType == db.FeedEventSetProfile
}

func (e *Event) IsSetProfilePic() bool {
	return e.FeedEvent.EventType == db.FeedEventSetProfilePic
}

func (e *Event) IsFollowUser() bool {
	return e.FeedEvent.EventType == db.FeedEventFollowUser
}

func (e *Event) IsFollowTopic() bool {
	return e.FeedEvent.EventType == db.FeedEventFollowTopic
}

func (e *Event) GetType() string {
	switch e.FeedEvent.EventType {
	case db.FeedEventPost:
		return "Post"
	case db.FeedEventPrivateMessage:
		return "PrivateMessage"
	case db.FeedEventReply:
		return "Reply"
	case db.FeedEventLike:
		return "Like"
	case db.FeedEventTopicPost:
		return "Topic Post"
	case db.FeedEventCreatePoll:
		return "Create Poll"
	case db.FeedEventPollVote:
		return "Poll Vote"
	case db.FeedEventSetName:
		return "Set Name"
	case db.FeedEventSetProfile:
		return "Set Profile"
	case db.FeedEventSetProfilePic:
		return "Set Profile Pic"
	case db.FeedEventFollowUser:
		return "Follow User"
	case db.FeedEventFollowTopic:
		return "Follow Topic"
	}
	return ""
}
