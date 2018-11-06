package profile

import (
	"bytes"
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

func GetPrivateMessages(recipientPrivate string, selfPkHash []byte, offset uint) ([]*Message, error) {
	dbMessages, err := db.GetPrivateMessages(offset)
	if err != nil {
		return nil, jerr.Get("error getting messages for hash", err)
	}
	messages, err := CreateMessagesFromDbMessages(recipientPrivate, selfPkHash, dbMessages)
	if err != nil {
		return nil, jerr.Get("error creating messages from db messages", err)
	}
	err = AttachNamesToMessages(messages)
	if err != nil {
		return nil, jerr.Get("error attaching names to posts", err)
	}
	err = AttachProfilePicsToMessages(messages)
	if err != nil {
		return nil, jerr.Get("error attaching profile pics to posts", err)
	}
	err = AttachPublicKeyToMessages(messages)
	if err != nil {
		return nil, jerr.Get("error attaching profile pics to posts", err)
	}
	return messages, nil
}

func CreateMessagesFromDbMessages(recipientPrivate string, selfPkHash []byte, dbMessages []*db.MemoPrivateMessage) ([]*Message, error) {
	var decryptedMessages []*Message
	for _, message := range dbMessages {
		var decrypted *Message
		if len(recipientPrivate) > 0 {
			// TODO: Run this concurrently, after switching from api to db pub key results, throttling
			text, err := util.DecryptPMWithAddress(message.Address, recipientPrivate, message.CompleteMessage)
			if err != nil {
				decrypted = &Message{
					Content:    message.CompleteMessage,
					SelfPkHash: selfPkHash,
					Memo:       message,
					Error:      err,
					Reply:      false,
				}
			} else {
				decrypted = &Message{
					Content:    text,
					SelfPkHash: selfPkHash,
					Memo:       message,
					Reply:      true,
				}
			}
		} else {
			decrypted = &Message{
				Content: message.CompleteMessage,
				Memo:    message,
				Reply:   false,
			}
		}
		decryptedMessages = append(decryptedMessages, decrypted)
	}
	return decryptedMessages, nil
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

// func SetShowMediaForPosts(posts []*Message, userId uint) error {
// 	if userId == 0 {
// 		for _, post := range posts {
// 			post.ShowMedia = true
// 		}
// 		return nil
// 	}
// 	settings, err := cache.GetUserSettings(userId)
// 	if err != nil {
// 		return jerr.Get("error getting user settings", err)
// 	}
// 	if settings.Integrations == db.SettingIntegrationsAll {
// 		for _, post := range posts {
// 			post.ShowMedia = true
// 		}
// 	}
// 	return nil
// }

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
