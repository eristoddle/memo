package memo

type OutputType uint

const (
	OutputTypeP2PK OutputType = iota
	OutputTypeReturn
	OutputTypeMemoMessage
	OutputTypeMemoSetName
	OutputTypeMemoFollow
	OutputTypeMemoUnfollow
	OutputTypeMemoLike
	OutputTypeMemoReply
	OutputTypeMemoSetProfile
	OutputTypeMemoTopicMessage
	OutputTypeMemoTopicFollow
	OutputTypeMemoTopicUnfollow
	OutputTypeMemoPollQuestionSingle
	OutputTypeMemoPollQuestionMulti
	OutputTypeMemoPollOption
	OutputTypeMemoPollVote
	OutputTypeMemoSetProfilePic
	OutputTypeMemoPrivateMessage
)

const (
	StringP2pk               = "p2pk"
	StringReturn             = "return"
	StringMemoMessage        = "memo-message"
	StringMemoSetName        = "memo-set-name"
	StringMemoFollow         = "memo-follow"
	StringMemoUnfollow       = "memo-unfollow"
	StringMemoLike           = "memo-like"
	StringMemoReply          = "memo-reply"
	StringMemoSetProfile     = "memo-set-profile"
	StringMemoSetProfilePic  = "memo-set-profile-pic"
	StringMemoTopicMessage   = "topic-message"
	StringMemoTopicFollow    = "topic-follow"
	StringMemoTopicUnfollow  = "topic-unfollow"
	StringMemoPollQuestion   = "poll-question"
	StringMemoPollOption     = "poll-option"
	StringMemoPollVote       = "poll-vote"
	StringMemoPrivateMessage = "private-message"
)

func (s OutputType) String() string {
	switch s {
	case OutputTypeP2PK:
		return StringP2pk
	case OutputTypeReturn:
		return StringReturn
	case OutputTypeMemoMessage:
		return StringMemoMessage
	case OutputTypeMemoSetName:
		return StringMemoSetName
	case OutputTypeMemoFollow:
		return StringMemoFollow
	case OutputTypeMemoUnfollow:
		return StringMemoUnfollow
	case OutputTypeMemoLike:
		return StringMemoLike
	case OutputTypeMemoReply:
		return StringMemoReply
	case OutputTypeMemoSetProfile:
		return StringMemoSetProfile
	case OutputTypeMemoTopicMessage:
		return StringMemoTopicMessage
	case OutputTypeMemoTopicFollow:
		return StringMemoTopicFollow
	case OutputTypeMemoTopicUnfollow:
		return StringMemoTopicUnfollow
	case OutputTypeMemoPollQuestionSingle, OutputTypeMemoPollQuestionMulti:
		return StringMemoPollQuestion
	case OutputTypeMemoPollOption:
		return StringMemoPollOption
	case OutputTypeMemoPollVote:
		return StringMemoPollVote
	case OutputTypeMemoSetProfilePic:
		return StringMemoSetProfilePic
	case OutputTypeMemoPrivateMessage:
		return StringMemoPrivateMessage
	default:
		return "unknown"
	}
}
