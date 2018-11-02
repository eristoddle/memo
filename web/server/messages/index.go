package messages

import (
	"fmt"
	"net/http"

	"github.com/jchavannes/jgo/jerr"
	"github.com/jchavannes/jgo/web"
	"github.com/memocash/memo/app/auth"
	"github.com/memocash/memo/app/db"
	"github.com/memocash/memo/app/profile"
	"github.com/memocash/memo/app/res"
)

var messagesRoute = web.Route{
	Pattern: res.UrlMessages,
	Handler: func(r *web.Response) {
		setMessagesFeed(r)
	},
}

func setMessagesFeed(r *web.Response) {
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

	userPkHash := key.PkHash
	offset := r.Request.GetUrlParameterInt("offset")
	messages, err := profile.GetPrivateMessages(userPkHash, uint(offset))
	if err != nil {
		r.Error(jerr.Get("error getting private messages", err), http.StatusInternalServerError)
		return
	}
	r.Helper["MessageItems"] = messages
	r.Helper["Offset"] = offset

	var prevOffset int
	if offset > 25 {
		prevOffset = offset - 25
	}
	page := offset/25 + 1
	r.Helper["Page"] = page
	r.Helper["OffsetLink"] = fmt.Sprintf("%s?", res.UrlActivity)
	r.Helper["PrevOffset"] = prevOffset
	r.Helper["NextOffset"] = offset + 25

	r.RenderTemplate(res.TmplActivity)
}
