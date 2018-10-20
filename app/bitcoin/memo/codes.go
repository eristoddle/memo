package memo

const (
	CodePrefix = 0x6d

	CodeTest              = 0x00
	CodeSetName           = 0x01
	CodePost              = 0x02
	CodeReply             = 0x03
	CodeLike              = 0x04
	CodeSetProfile        = 0x05
	CodeFollow            = 0x06
	CodeUnfollow          = 0x07
	CodeSetImageBaseUrl   = 0x08
	CodeAttachPicture     = 0x09
	CodeSetProfilePicture = 0x0a
	CodeRepost            = 0x0b
	CodeTopicMessage      = 0x0c
	CodeTopicFollow       = 0x0d
	CodeTopicUnfollow     = 0x0e

	CodePollCreate     = 0x10
	CodePollOption     = 0x13
	CodePollVote       = 0x14
	CodePrivateMessage = 0x15
)

const (
	CodePollTypeSingle = 0x01
	CodePollTypeMulti  = 0x02
	CodePollTypeRank   = 0x03
)

func GetAllCodes() [][]byte {
	return [][]byte{
		{CodePrefix, CodeTest},
		{CodePrefix, CodeSetName},
		{CodePrefix, CodePost},
		{CodePrefix, CodeReply},
		{CodePrefix, CodeLike},
		{CodePrefix, CodeSetProfile},
		{CodePrefix, CodeFollow},
		{CodePrefix, CodeUnfollow},
		{CodePrefix, CodeSetImageBaseUrl},
		{CodePrefix, CodeAttachPicture},
		{CodePrefix, CodeSetProfilePicture},
		{CodePrefix, CodeRepost},
		{CodePrefix, CodeTopicMessage},
		{CodePrefix, CodePollCreate},
		{CodePrefix, CodePollOption},
		{CodePrefix, CodePollVote},
		{CodePrefix, CodeTopicFollow},
		{CodePrefix, CodeTopicUnfollow},
		{CodePrefix, CodePrivateMessage},
	}
}

func GetCodeString(code byte) string {
	switch code {
	case CodeSetName:
		return StringMemoSetName
	case CodePost:
		return StringMemoMessage
	case CodeReply:
		return StringMemoReply
	case CodeLike:
		return StringMemoLike
	case CodeSetProfile:
		return StringMemoSetProfile
	case CodeFollow:
		return StringMemoFollow
	case CodeUnfollow:
		return StringMemoUnfollow
	case CodeSetProfilePicture:
		return StringMemoSetProfilePic
	case CodePollCreate:
		return StringMemoPollQuestion
	case CodePollOption:
		return StringMemoPollOption
	case CodePollVote:
		return StringMemoPollVote
	case CodeTopicMessage:
		return StringMemoTopicMessage
	case CodeTopicFollow:
		return StringMemoTopicFollow
	case CodeTopicUnfollow:
		return StringMemoTopicUnfollow
	case CodePrivateMessage:
		return StringMemoPrivateMessage
	default:
		return "unknown"
	}
}
