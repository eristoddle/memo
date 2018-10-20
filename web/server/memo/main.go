package memo

import "github.com/jchavannes/jgo/web"

var urlAddress = web.UrlParam{
	Id:   "address",
	Type: web.UrlParamString,
}

var urlTxHash = web.UrlParam{
	Id:   "tx-hash",
	Type: web.UrlParamString,
}

func GetRoutes() []web.Route {
	return []web.Route{
		newRoute,
		newSubmitRoute,
		setNameRoute,
		setNameSubmitRoute,
		followRoute,
		followSubmitRoute,
		unfollowRoute,
		unfollowSubmitRoute,
		privateMessageRoute,
		privateMessageSubmitRoute,
		postRoute,
		postAjaxRoute,
		postThreadedAjaxRoute,
		postThreadedRoute,
		postMoreThreadedAjaxRoute,
		likeRoute,
		likeSubmitRoute,
		replyRoute,
		replySubmitRoute,
		waitRoute,
		waitSubmitRoute,
		setProfileRoute,
		setProfileSubmitRoute,
		setPicRoute,
		setPicSubmitRoute,
		setLangRoute,
	}
}
