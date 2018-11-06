package memo

import (
	"bytes"
	"net/http"

	"github.com/jchavannes/jgo/jerr"
	"github.com/jchavannes/jgo/web"
	"github.com/memocash/memo/app/auth"
	"github.com/memocash/memo/app/bitcoin/transaction"
	"github.com/memocash/memo/app/bitcoin/transaction/build"
	"github.com/memocash/memo/app/bitcoin/wallet"
	"github.com/memocash/memo/app/db"
	"github.com/memocash/memo/app/mutex"
	"github.com/memocash/memo/app/profile"
	"github.com/memocash/memo/app/res"
)

var privateMessageRoute = web.Route{
	Pattern:    res.UrlMemoPrivateMessage + "/" + urlAddress.UrlPart(),
	NeedsLogin: true,
	Handler: func(r *web.Response) {
		addressString := r.Request.GetUrlNamedQueryVariable(urlAddress.Id)
		address := wallet.GetAddressFromString(addressString)
		pkHash := address.GetScriptAddress()
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
		if bytes.Equal(key.PkHash, pkHash) {
			r.SetRedirect(res.GetUrlWithBaseUrl(res.UrlIndex, r))
			return
		}
		hasSpendableTxOut, err := db.HasSpendable(key.PkHash)
		if err != nil {
			r.Error(jerr.Get("error getting spendable tx out", err), http.StatusInternalServerError)
			return
		}
		if !hasSpendableTxOut {
			r.SetRedirect(res.UrlNeedFunds)
			return
		}

		pf, err := profile.GetProfile(pkHash, key.PkHash)
		if err != nil {
			r.Error(jerr.Get("error getting profile for hash", err), http.StatusInternalServerError)
			return
		}

		r.Helper["Profile"] = pf
		r.RenderTemplate(res.UrlMemoPrivateMessage)
	},
}

var privateMessageSubmitRoute = web.Route{
	Pattern:     res.UrlMemoPrivateMessageSubmit,
	NeedsLogin:  true,
	CsrfProtect: true,
	Handler: func(r *web.Response) {
		addressString := r.Request.GetFormValue("address")
		message := r.Request.GetFormValue("message")
		pubkey := r.Request.GetFormValue("pubkey")
		messageAddress := wallet.GetAddressFromString(addressString)
		if messageAddress.GetEncoded() != addressString {
			r.Error(jerr.New("error parsing address"), http.StatusUnprocessableEntity)
			return
		}
		password := r.Request.GetFormValue("password")
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

		privateKey, err := key.GetPrivateKey(password)
		if err != nil {
			r.Error(jerr.Get("error getting private key", err), http.StatusUnauthorized)
			return
		}

		pkHash := privateKey.GetPublicKey().GetAddress().GetScriptAddress()
		mutex.Lock(pkHash)

		txns, err := build.PrivateMessage(message, privateKey, pubkey)
		if err != nil {
			var statusCode = http.StatusInternalServerError
			if build.IsNotEnoughValueError(err) {
				statusCode = http.StatusPaymentRequired
			}
			mutex.Unlock(pkHash)
			r.Error(jerr.Get("error building private message tx", err), statusCode)
			return
		}

		for _, txn := range txns {
			transaction.GetTxInfo(txn).Print()
			transaction.QueueTx(txn)
		}

		r.Write(txns[len(txns)-1].MsgTx.TxHash().String())
	},
}
