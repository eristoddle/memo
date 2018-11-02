package profile

import (
	"github.com/jchavannes/jgo/jerr"
	"github.com/memocash/memo/app/db"
)

type Message struct {
	Encrypted string
	PkHash    []byte
}

// type MessageContainer struct {
// 	PkHash     []byte
// 	Count      int
// 	DbMessages []*db.MemoPrivateMessage
// }

func GetPrivateMessages(selfPkHash []byte, offset uint) ([]*Message, error) {
	dbMessages, err := db.GetPrivateMessages(offset)
	if err != nil {
		return nil, jerr.Get("error getting messages for hash", err)
	}
	messages, err := CreateMessagesFromDbMessages(selfPkHash, dbMessages)
	if err != nil {
		return nil, jerr.Get("error creating messages from db messages", err)
	}
	return messages, nil
}

func CreateMessagesFromDbMessages(selfPkHash []byte, dbMessages []*db.MemoPrivateMessage) ([]*Message, error) {
	var messages []*Message
	for _, dbMessage := range dbMessages {
		message := &Message{
			Encrypted: dbMessage.Message,
			PkHash:    selfPkHash,
		}
		messages = append(messages, message)
	}

	return messages, nil
}
