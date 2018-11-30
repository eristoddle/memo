package profile

import "github.com/jchavannes/jgo/web"

var urlAddress = web.UrlParam{
	Id:   "address",
	Type: web.UrlParamString,
}

func GetRoutes() []web.Route {
	return []web.Route{
		allRoute,
		mostActionsRoute,
		mostFollowersRoute,
		viewRoute,
		followersRoute,
		followingRoute,
		accountRoute,
		settingsRoute,
		settingsSubmitRoute,
		notificationsRoute,
		topicsFollowingRoute,
		coinsRoute,
		miniRoute,
		newRoute,
		privateMessagesRoute,
	}
}
