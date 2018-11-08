package posts

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/jchavannes/jgo/jerr"
	"github.com/jchavannes/jgo/web"
	"github.com/memocash/memo/app/auth"
	"github.com/memocash/memo/app/db"
	"github.com/memocash/memo/app/profile"
	"github.com/memocash/memo/app/res"
)

var messagesRoute = web.Route{
	Pattern:    res.UrlPostsMessages,
	NeedsLogin: true,
	Handler: func(r *web.Response) {
		getPrivateMessages(r)
	},
}

func getPrivateMessages(r *web.Response) {
	preHandler(r)
	user, err := auth.GetSessionUser(r.Session.CookieId)
	if err != nil {
		r.Error(jerr.Get("error getting session user", err), http.StatusInternalServerError)
		return
	}
	key, err := db.GetKeyForUser(user.Id)
	if err != nil {
		r.Error(jerr.Get("error getting key for user", err), http.StatusInternalServerError)
		return
	}
	offset := r.Request.GetUrlParameterInt("offset")
	var messages []*profile.Message
	decrypted := false
	password := r.Request.GetFormValue("password")
	if len(password) > 0 {
		decrypted = true
		privateKey, err := key.GetPrivateKey(password)
		if err != nil {
			r.Error(jerr.Get("error getting private key", err), http.StatusUnauthorized)
			return
		}
		hexPk := privateKey.GetHex()
		messages, err = profile.GetPrivateMessages(hexPk, key.PkHash, uint(offset))
		if err != nil {
			r.Error(jerr.Get("error getting private messages", err), http.StatusInternalServerError)
			return
		}
	} else {
		messages, err = profile.GetPrivateMessages("", []byte(""), uint(offset))
	}

	res.SetPageAndOffset(r, offset)
	r.Helper["Decrypted"] = decrypted
	r.Helper["OffsetLink"] = fmt.Sprintf("%s?", strings.TrimLeft(res.UrlPostsMessages, "/"))
	r.Helper["Posts"] = messages
	r.Helper["Title"] = "Memo - Private Messages"
	r.Render()
}
