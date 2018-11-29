package cache

import (
	"fmt"

	"github.com/jchavannes/jgo/jerr"
	"github.com/memocash/memo/app/bitcoin/wallet"
	"github.com/memocash/memo/app/db"
)

type UnreadMessages struct {
	Count uint
}

func GetUnreadMessageCount(userId uint) (uint, error) {
	var unreadMessages UnreadMessages
	err := GetItem(getUnreadMessageName(userId), &unreadMessages)
	if err == nil {
		return unreadMessages.Count, nil
	}
	if !IsMissError(err) {
		return 0, jerr.Get("error getting pk hash from cache", err)
	}
	unreadCount, err := GetAndSetUnreadMessageCount(userId)
	if err != nil {
		return 0, jerr.Get("error setting user last message id cache", err)
	}
	return unreadCount, nil
}

func GetAndSetUnreadMessageCount(userId uint) (uint, error) {
	lastMessageId, err := db.GetLastMessageId(userId)
	if err != nil {
		return 0, jerr.Get("error getting last message id from db", err)
	}
	address, err := GetUserAddress(userId)
	if err != nil {
		return 0, jerr.Get("error getting user pk hash", err)
	}
	unreadCount, err := db.GetUnreadMessageCount(address.GetEncoded(), lastMessageId)
	if err != nil {
		return 0, jerr.Get("error getting unread count", err)
	}
	err = SetUnreadMessageCount(userId, unreadCount)
	if err != nil {
		return 0, jerr.Get("error setting unread message count in cache", err)
	}
	return unreadCount, nil
}

func SetUnreadMessageCount(userId uint, count uint) error {
	err := SetItem(getUnreadMessageName(userId), UnreadMessages{
		Count: count,
	})
	if err != nil {
		return jerr.Get("error setting user last message id cache", err)
	}
	return nil
}

func getUnreadMessageName(userId uint) string {
	return fmt.Sprintf("user-unread-messages-%d", userId)
}

func BatchSetUnreadMessageCount(memoPrivateMessage *db.MemoPrivateMessage) error {
	address := wallet.GetAddressFromString(memoPrivateMessage.RecipientAddress)
	pkHash := address.GetScriptAddress()
	userId, err := db.GetUserIdFromPkHash(pkHash)
	if err != nil {
		return jerr.Get("error getting user id from pkhash", err)
	}
	lastMessageId, err := db.GetLastMessageId(userId)
	if err != nil {
		return jerr.Get("error getting last message id from db", err)
	}
	unreadCount, err := db.GetUnreadMessageCount(address.GetEncoded(), lastMessageId)
	if err != nil {
		return jerr.Get("error getting unread count", err)
	}
	err = SetUnreadMessageCount(userId, unreadCount)
	if err != nil {
		return jerr.Get("error setting unread message count in cache", err)
	}
	return nil
}
