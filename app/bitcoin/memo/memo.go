package memo

const (
	MaxPostSize                = 217
	MaxReplySize               = 184
	MaxTagMessageSize          = 217
	MaxPollQuestionSize        = 209
	MaxPollOptionSize          = 184
	MaxVoteCommentSize         = 184
	MaxPrivateMessageSizeChunk = 184
)

// https://bitcoin.stackexchange.com/questions/1195/how-to-calculate-transaction-size-before-sending-legacy-non-segwit-p2pkh-p2sh
const (
	MaxTxFee          = 425
	OutputFeeP2PKH    = 34
	OutputFeeOpReturn = 20
	OutputOpDataFee   = 3
	InputFeeP2PKH     = 148
	BaseTxFee         = 10
)

const DustMinimumOutput int64 = 546

type PollType string

const (
	PollTypeOne  PollType = "one"
	PollTypeAny  PollType = "any"
	PollTypeRank PollType = "rank"
)
