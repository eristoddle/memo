package profile

import (
	"bytes"
	"encoding/hex"
	"strings"

	"github.com/jchavannes/jgo/jerr"
	"github.com/memocash/memo/app/db"
	"github.com/memocash/memo/app/util"
	"github.com/memocash/memo/app/util/format"
)

type Message struct {
	Content    string
	SelfPkHash []byte
	PublicKey  []byte
	Address    string
	Memo       *db.MemoPrivateMessage
	Error      error
	Name       string
	ProfilePic *db.MemoSetPic
	ShowMedia  bool
	Reply      bool
}

func (p Message) IsLoggedIn() bool {
	return len(p.SelfPkHash) > 0
}

func (p Message) GetMessage() string {
	var msg = p.Content
	if p.ShowMedia {
		msg = format.AddYoutubeVideos(msg)
		msg = format.AddImgurImages(msg)
		msg = format.AddGiphyImages(msg)
		msg = format.AddTwitterImages(msg)
		msg = format.AddRedditImages(msg)
		msg = format.AddTweets(msg)
	}
	msg = strings.TrimSpace(msg)
	msg = format.AddLinks(msg)
	return msg
}

func GetPrivateMessages(recipientPrivate string, selfPkHash []byte, recipient string, offset uint) ([]*Message, error) {
	dbMessages, err := db.GetPrivateMessages(recipient, offset)
	if err != nil {
		return nil, jerr.Get("error getting messages for hash", err)
	}
	messages := CreateMessagesFromDbMessages(selfPkHash, dbMessages)
	err = AttachPublicKeyToMessages(messages)
	if err != nil {
		return nil, jerr.Get("error attaching profile pics to messages", err)
	}
	err = AttachNamesToMessages(messages)
	if err != nil {
		return nil, jerr.Get("error attaching names to messages", err)
	}
	err = AttachProfilePicsToMessages(messages)
	if err != nil {
		return nil, jerr.Get("error attaching profile pics to messages", err)
	}
	err = DecryptMessages(recipientPrivate, messages)
	if err != nil {
		return nil, jerr.Get("error decrypting messages", err)
	}
	return messages, nil
}

func CreateMessagesFromDbMessages(selfPkHash []byte, dbMessages []*db.MemoPrivateMessage) []*Message {
	var messages []*Message
	for _, dbMessage := range dbMessages {
		message := &Message{
			SelfPkHash: selfPkHash,
			Memo:       dbMessage,
		}
		messages = append(messages, message)
	}
	return messages
}

func DecryptMessages(recipientPrivate string, messages []*Message) error {
	for _, message := range messages {
		if len(recipientPrivate) > 0 {
			hexPubkey := hex.EncodeToString(message.PublicKey)
			text, err := util.DecryptPM(hexPubkey, recipientPrivate, message.Memo.CompleteMessage)
			if err != nil {
				message.Content = message.Memo.CompleteMessage
				message.Error = err
				message.Reply = false
			} else {
				message.Content = text
				message.Reply = true
			}
		} else {
			message.Content = message.Memo.CompleteMessage
			message.Reply = false
		}
	}
	return nil
}

func AttachNamesToMessages(messages []*Message) error {
	var namePkHashes [][]byte
	for _, message := range messages {
		for _, namePkHash := range namePkHashes {
			if bytes.Equal(namePkHash, message.Memo.PkHash) {
				continue
			}
		}
		namePkHashes = append(namePkHashes, message.Memo.PkHash)
	}
	setNames, err := db.GetNamesForPkHashes(namePkHashes)
	if err != nil {
		return jerr.Get("error getting set names for pk hashes", err)
	}
	for _, setName := range setNames {
		for _, message := range messages {
			if bytes.Equal(message.Memo.PkHash, setName.PkHash) {
				message.Name = setName.Name
			}
		}
	}
	return nil
}

func AttachProfilePicsToMessages(messages []*Message) error {
	var namePkHashes [][]byte
	for _, message := range messages {
		for _, namePkHash := range namePkHashes {
			if bytes.Equal(namePkHash, message.Memo.PkHash) {
				continue
			}
		}
		namePkHashes = append(namePkHashes, message.Memo.PkHash)
	}
	setPics, err := db.GetPicsForPkHashes(namePkHashes)
	if err != nil {
		return jerr.Get("error getting profile pics for pk hashes", err)
	}
	for _, setPic := range setPics {
		for _, message := range messages {
			if bytes.Equal(message.Memo.PkHash, setPic.PkHash) {
				message.ProfilePic = setPic
			}
		}
	}
	return nil
}

func AttachPublicKeyToMessages(messages []*Message) error {
	var namePkHashes [][]byte
	for _, message := range messages {
		for _, namePkHash := range namePkHashes {
			if bytes.Equal(namePkHash, message.Memo.PkHash) {
				continue
			}
		}
		namePkHashes = append(namePkHashes, message.Memo.PkHash)
	}
	keys, err := db.GetKeysForPkHashes(namePkHashes)
	if err != nil {
		return jerr.Get("error getting public keys for pk hashes", err)
	}
	for _, key := range keys {
		for _, message := range messages {
			if bytes.Equal(message.Memo.PkHash, key.PkHash) {
				message.PublicKey = key.PublicKey
			}
		}
	}
	return nil
}

func (p Message) GetTimeString(timezone string) string {
	if p.Memo.BlockId != 0 {
		if p.Memo.Block != nil {
			return util.GetTimezoneTime(p.Memo.Block.Timestamp, timezone)
		} else {
			return "Unknown"
		}
	}
	return "Unconfirmed"
}

func (p Message) GetTimeAgo() string {
	if p.Memo.Block != nil && p.Memo.Block.Timestamp.Before(p.Memo.CreatedAt) {
		return util.GetTimeAgo(p.Memo.Block.Timestamp)
	} else {
		return util.GetTimeAgo(p.Memo.CreatedAt)
	}
}

func (p Message) GetId() uint {
	if p.Memo == nil {
		return 0
	}
	return p.Memo.Id
}
