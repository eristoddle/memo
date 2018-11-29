package db

import (
	"time"

	"github.com/jchavannes/jgo/jerr"
)

type UserMessage struct {
	Id            uint `gorm:"primary_key"`
	UserId        uint
	LastMessageId uint
	CreatedAt     time.Time
	UpdatedAt     time.Time
}

func GetLastMessageId(userId uint) (uint, error) {
	var userMessage UserMessage
	err := find(&userMessage, UserMessage{
		UserId: userId,
	})
	if err == nil {
		return userMessage.LastMessageId, nil
	}
	if !IsRecordNotFoundError(err) {
		return 0, jerr.Get("error finding last message", err)
	}
	return 0, nil
}

func SetLastMessageId(userId uint, lastMessageId uint) error {
	var userMessage UserMessage
	err := find(&userMessage, UserMessage{
		UserId: userId,
	})
	if err != nil {
		if !IsRecordNotFoundError(err) {
			return jerr.Get("error getting last user message from db", err)
		}
		userMessage = UserMessage{
			UserId:        userId,
			LastMessageId: lastMessageId,
		}
		err := create(&userMessage)
		if err != nil {
			return jerr.Get("error creating user message", err)
		}
		return nil
	} else {
		userMessage.LastMessageId = lastMessageId
		result := save(userMessage)
		if result.Error != nil {
			return jerr.Get("error saving user message", result.Error)
		}
		return nil
	}
}
