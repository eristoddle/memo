package posts

import "github.com/jchavannes/jgo/web"

func GetRoutes() []web.Route {
	return []web.Route{
		newRoute,
		topRoute,
		rankedRoute,
		archiveRoute,
		personalizedRoute,
		pollsRoute,
		threadsRoute,
		messagesRoute,
	}
}

func preHandler(r *web.Response) {
	r.Helper["Nav"] = "posts"
}
