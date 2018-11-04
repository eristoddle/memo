package res

import "github.com/jchavannes/jgo/web"

const (
	UrlIndex           = "/"
	UrlProtocol        = "/protocol"
	UrlGuides          = "/guides"
	UrlDisclaimer      = "/disclaimer"
	UrlIntroducing     = "/introducing-memo"
	UrlOpenSource      = "/open-sourcing-memo"
	UrlNeedFunds       = "/need-funds"
	UrlNewPosts        = "/new-posts"
	UrlStats           = "/stats"
	UrlCharts          = "/charts"
	UrlActivity        = "/activity"
	UrlAbout           = "/about"
	UrlNotFound        = "/404"
	UrlMemoSetLanguage = "/set-language"
	UrlAll             = "/all"

	TmplAll              = "/index/all"
	TmplAbout            = "/index/about"
	TmplDashboard        = "/index/dashboard"
	TmplDashboardNoFunds = "/index/dashboard-no-funds"
	TmplDisclaimer       = "/index/disclaimer"
	TmplActivity         = "/index/activity"
	TmplGuides           = "/index/guides"
	TmplIntroducing      = "/index/introducing-memo"
	TmplNeedFunds        = "/index/need-funds"
	TmplOpenSource       = "/index/open-source"
	TmplProtocol         = "/index/protocol"
	TmplStats            = "/index/stats"
	TmplCharts           = "/index/charts"
)

const (
	UrlSignup       = "/signup"
	UrlSignupSubmit = "/signup-submit"
	UrlLogin        = "/login"
	UrlLoginSubmit  = "/login-submit"
	UrlLogout       = "/logout"

	TmplSignup = "/auth/signup"
	TmplLogin  = "/auth/login"
)

const (
	UrlKeyExport               = "/key/export"
	UrlKeyLoad                 = "/key/load"
	UrlKeyChangePassword       = "/key/change-password"
	UrlKeyChangePasswordSubmit = "/key/change-password-submit"
	UrlKeyDeleteAccount        = "/key/delete-account"
	UrlKeyDeleteAccountSubmit  = "/key/delete-account-submit"
)

const (
	UrlMemoNew                  = "/memo/new"
	UrlMemoNewSubmit            = "/memo/new-submit"
	UrlMemoSetName              = "/memo/set-name"
	UrlMemoSetNameSubmit        = "/memo/set-name-submit"
	UrlMemoFollow               = "/memo/follow"
	UrlMemoFollowSubmit         = "/memo/follow-submit"
	UrlMemoUnfollow             = "/memo/unfollow"
	UrlMemoUnfollowSubmit       = "/memo/unfollow-submit"
	UrlMemoPrivateMessage       = "/memo/private-message"
	UrlMemoPrivateMessageSubmit = "/memo/private-message-submit"
	UrlMemoPost                 = "/post"
	UrlMemoPostThreaded         = "/post-threaded"
	UrlMemoPostMoreThreadedAjax = "/post-more-threaded-ajax"
	UrlMemoPostThreadedAjax     = "/post-threaded-ajax"
	UrlMemoPostAjax             = "/post-ajax"
	UrlMemoLike                 = "/memo/like"
	UrlMemoLikeSubmit           = "/memo/like-submit"
	UrlMemoReply                = "/memo/reply"
	UrlMemoReplySubmit          = "/memo/reply-submit"
	UrlMemoWait                 = "/memo/wait"
	UrlMemoWaitSubmit           = "/memo/wait-submit"
	UrlMemoSetProfile           = "/memo/set-profile"
	UrlMemoSetProfileSubmit     = "/memo/set-profile-submit"
	UrlMemoSetProfilePic        = "/memo/set-profile-pic"
	UrlMemoSetProfilePicSubmit  = "/memo/set-profile-pic-submit"

	TmplMemoPost         = "/memo/post"
	TmplMemoPostThreaded = "/memo/post-threaded"
)

const (
	UrlProfiles               = "/profiles"
	UrlProfilesNew            = "/profiles/new"
	UrlProfilesMostActions    = "/profiles/most-actions"
	UrlProfilesMostFollowers  = "/profiles/most-followers"
	UrlProfileView            = "/profile"
	UrlProfileFollowers       = "/profile/followers"
	UrlProfileFollowing       = "/profile/following"
	UrlProfileSettings        = "/settings"
	UrlProfileAccount         = "/account"
	UrlProfileCoins           = "/coins"
	UrlProfileSettingsSubmit  = "/settings-submit"
	UrlProfileNotifications   = "/notifications"
	UrlProfileTopicsFollowing = "/profile/topics-following"
	UrlProfileMini            = "/profile/mini"

	TmplProfiles              = "/profile/all"
	TmplProfilesNew           = "/profile/new"
	TmplProfileSettings       = "/profile/settings"
	TmplProfileAccount        = "/profile/account"
	TmplProfileCoins          = "/profile/coins"
	TmplProfileNotifications  = "/profile/notifications"
	TmplProfilesMostActions   = "/profile/most-actions"
	TmplProfilesMostFollowers = "/profile/most-followers"
)

const (
	UrlPostsNew          = "/posts/new"
	UrlPostsTop          = "/posts/top"
	UrlPostsRanked       = "/posts/ranked"
	UrlPostsThreads      = "/posts/threads"
	UrlPostsPolls        = "/polls"
	UrlPostsArchive      = "/posts/archive"
	UrlPostsPersonalized = "/posts/personalized"
	UrlPostsMessages     = "/posts/messages"

	TmplPostsPolls = "/posts/polls"
)

const (
	UrlTopics             = "/topics"
	UrlTopicsAll          = "/topics/all"
	UrlTopicsMostFollowed = "/topics/most-followed"
	UrlTopicsMostPosts    = "/topics/most-posts"
	UrlTopicsFollowing    = "/topics/following"
	UrlTopicsCreate       = "/topics/create"
	UrlTopicsCreateSubmit = "/topics/create-submit"
	UrlTopicView          = "/topic"
	UrlTopicThreads       = "/topics/threads"
	UrlTopicsSocket       = "/topics/socket"
	UrlTopicsMorePosts    = "/topics/more-posts"
	UrlTopicsPostAjax     = "/topics/post-ajax"
	UrlTopicsFollowSubmit = "/topics/follow-submit"
	UrlTopicsFollowers    = "/topics/followers"

	TmplTopicView = "/topics/view"
	TmplTopicPost = "/topics/post"
)

const (
	UrlPollCreate       = "/poll/create"
	UrlPollCreateSubmit = "/poll/create-submit"
	UrlPollVoteSubmit   = "/poll/vote-submit"
	UrlPollVotesAjax    = "/poll/votes-ajax"
)

const (
	TmplSnippetsPost                 = "/post/post"
	TmplSnippetsPostThreaded         = "/post/post-threaded"
	TmplSnippetsPostThreadedLoadMore = "/post/snippets/post-threaded-load-more"
)

func GetBaseUrl(r *web.Response) string {
	baseUrl := r.Request.GetHeader("AppPath")
	if baseUrl == "" {
		baseUrl = "/"
	}
	return baseUrl
}

func GetUrlWithBaseUrl(url string, r *web.Response) string {
	baseUrl := GetBaseUrl(r)
	baseUrl = baseUrl[:len(baseUrl)-1]
	return baseUrl + url
}
