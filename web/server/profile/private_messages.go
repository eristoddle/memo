package profile

import (
	"net/http"

	"github.com/jchavannes/jgo/jerr"
	"github.com/jchavannes/jgo/web"
	"github.com/memocash/memo/app/auth"
	"github.com/memocash/memo/app/db"
	"github.com/memocash/memo/app/profile"
	"github.com/memocash/memo/app/res"
)

var privateMessagesRoute = web.Route{
	Pattern:    res.UrlProfilePrivateMessages,
	NeedsLogin: true,
	Handler: func(r *web.Response) {
		getPrivateMessages(r)
	},
}

// TODO: refactor this to remove things
func getPrivateMessages(r *web.Response) {
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
	address := key.GetAddress().GetEncoded()
	if len(password) > 0 {
		decrypted = true
		privateKey, err := key.GetPrivateKey(password)
		if err != nil {
			r.Error(jerr.Get("error getting private key", err), http.StatusUnauthorized)
			return
		}
		hexPk := privateKey.GetHex()
		messages, err = profile.GetPrivateMessages(hexPk, key.PkHash, address, uint(offset))
		if err != nil {
			r.Error(jerr.Get("error getting private messages", err), http.StatusInternalServerError)
			return
		}
	} else {
		messages, err = profile.GetPrivateMessages("", []byte(""), address, uint(offset))
	}

	res.SetPageAndOffset(r, offset)
	r.Helper["Decrypted"] = decrypted
	r.Helper["Posts"] = messages
	r.RenderTemplate(res.TmplProfilePrivateMessages)
}
