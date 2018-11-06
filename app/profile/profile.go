package profile

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcutil"
	"github.com/jchavannes/bchutil"
	"github.com/jchavannes/jgo/jerr"
	"github.com/memocash/memo/app/bitcoin/wallet"
	"github.com/memocash/memo/app/cache"
	"github.com/memocash/memo/app/db"
	"github.com/memocash/memo/app/obj/rep"
	"github.com/memocash/memo/app/util"
	"github.com/memocash/memo/app/util/format"
	"github.com/skip2/go-qrcode"
)

type Profile struct {
	Name                 string
	PkHash               []byte
	NameTx               []byte
	Profile              string
	ProfileTx            []byte
	Self                 bool
	SelfPkHash           []byte
	Balance              int64
	BalanceBCH           float64
	hasBalance           bool
	FollowerCount        int
	FollowingCount       int
	TopicsFollowingCount int
	NumPosts             int
	FirstPost            time.Time
	LastPost             time.Time
	Followers            []*Follower
	Following            []*Follower
	Reputation           *rep.Reputation
	CanFollow            bool
	CanUnfollow          bool
	Qr                   string
	Pic                  *db.MemoSetPic
}

func (p Profile) GetFirstPost(timezone string) string {
	return util.GetTimezoneTime(p.FirstPost, timezone)
}

func (p Profile) GetLastPost(timezone string) string {
	return util.GetTimezoneTime(p.LastPost, timezone)
}

func (p Profile) GetJoined() string {
	return p.FirstPost.Format("Jan 02, 2006")
}

func (p Profile) IsSelf() bool {
	return bytes.Equal(p.PkHash, p.SelfPkHash)
}

func (p Profile) HasBalance() bool {
	return p.hasBalance
}

func (p Profile) NameSet() bool {
	return len(p.NameTx) > 0
}

func (p Profile) GetNameTx() string {
	hash, err := chainhash.NewHash(p.NameTx)
	if err != nil {
		return ""
	}
	return hash.String()
}

func (p Profile) GetAddressString() string {
	addr, err := btcutil.NewAddressPubKeyHash(p.PkHash, &wallet.MainNetParamsOld)
	if err != nil {
		return ""
	}
	return addr.String()
}

func (p Profile) GetCashAddressString() string {
	addr, err := btcutil.NewAddressPubKeyHash(p.PkHash, &wallet.MainNetParamsOld)
	if err != nil {
		return ""
	}
	cashAddr, err := bchutil.NewCashAddressPubKeyHash(addr.ScriptAddress(), &wallet.MainNetParamsOld)
	if err != nil {
		return ""
	}
	return cashAddr.String()
}

func (p Profile) GetCashAddressOnlyString() string {
	cashAddr := p.GetCashAddressString()
	return strings.TrimPrefix(cashAddr, "bitcoincash:")
}

func (p *Profile) SetBalances() error {
	bal, err := cache.GetBalance(p.PkHash)
	if err != nil {
		return jerr.Get("error getting balance from cache", err)
	}
	p.Balance = bal
	p.BalanceBCH = float64(bal) * 1e-8
	p.hasBalance = true
	return nil
}

func (p *Profile) SetFollowerCount() error {
	cnt, err := db.GetFollowerCountForPkHash(p.PkHash)
	if err != nil {
		return jerr.Get("error getting follower count for hash", err)
	}
	p.FollowerCount = int(cnt)
	return nil
}

func (p *Profile) SetFollowingCount() error {
	cnt, err := db.GetFollowingCountForPkHash(p.PkHash)
	if err != nil {
		return jerr.Get("error getting following count for hash", err)
	}
	p.FollowingCount = int(cnt)
	return nil
}

func (p *Profile) SetTopicsFollowingCount() error {
	cnt, err := db.GetMemoTopicFollowCountForUser(p.PkHash)
	if err != nil {
		return jerr.Get("error getting topic following count for hash", err)
	}
	p.TopicsFollowingCount = int(cnt)
	return nil
}

func (p *Profile) SetCanFollow() error {
	canFollow, err := CanFollow(p.PkHash, p.SelfPkHash)
	if err != nil {
		return jerr.Get("error getting can follow", err)
	}
	p.CanFollow = canFollow
	p.CanUnfollow = !canFollow && bytes.Compare(p.PkHash, p.SelfPkHash) != 0
	return nil
}

func (p *Profile) SetUserStats() error {
	userStat, err := db.GetUserStat(p.PkHash)
	if err != nil {
		if db.IsRecordNotFoundError(err) {
			return nil
		}
		return jerr.Get("error getting num posts", err)
	}
	p.NumPosts = userStat.NumPosts
	p.FirstPost = userStat.FirstPost
	p.LastPost = userStat.LastPost
	return nil
}

func (p *Profile) SetReputation() error {
	reputation, err := rep.GetReputation(p.SelfPkHash, p.PkHash)
	if err != nil {
		return jerr.Get("error getting reputation", err)
	}
	p.Reputation = reputation
	return nil
}

func (p *Profile) SetQr() error {
	var qr *qrcode.QRCode
	qr, err := qrcode.New(p.GetCashAddressString(), qrcode.Medium)
	if err != nil {
		return jerr.Get("error generating qr", err)
	}
	png, err := qr.PNG(250)
	if err != nil {
		return jerr.Get("error generating png", err)
	}
	p.Qr = base64.StdEncoding.EncodeToString(png)
	return nil
}

func (p Profile) GetText() string {
	var profile = p.Profile
	if profile == "" {
		return "Profile not set"
	}
	profile = strings.TrimSpace(profile)
	profile = format.AddLinks(profile)
	return profile
}

func (p Profile) GetPublicKey() (string, error) {
	pubKey, err := db.GetPublickKeyFromPkHash(p.PkHash)
	if err != nil {
		return "", jerr.Get("error pubkey for hash", err)
	}
	hexPubkey := hex.EncodeToString(pubKey)
	return hexPubkey, nil
}

func GetProfiles(selfPkHash []byte, searchString string, offset int, orderType db.UserStatOrderType) ([]*Profile, error) {
	objProfiles, err := db.GetUniqueMemoAPkHashes(offset, searchString, orderType)
	if err != nil {
		return nil, jerr.Get("error getting profiles from db", err)
	}
	var profiles []*Profile
	for _, objProfile := range objProfiles {
		profile, err := GetProfile(objProfile.PkHash, selfPkHash)
		if err != nil {
			return nil, jerr.Get("error getting profile for hash", err)
		}
		profile.NumPosts = objProfile.NumPosts
		profile.FollowerCount = objProfile.NumFollowers
		profile.FirstPost = objProfile.FirstPost
		profile.LastPost = objProfile.LastPost
		profiles = append(profiles, profile)
	}
	return profiles, nil
}

func AttachReputationToProfiles(profiles []*Profile) error {
	for _, profile := range profiles {
		err := profile.SetReputation()
		if err != nil {
			return jerr.Get("error setting reputation", err)
		}
	}
	return nil
}

func GetProfile(pkHash []byte, selfPkHash []byte) (*Profile, error) {
	var name string
	var nameTx []byte
	memoSetName, err := db.GetNameForPkHash(pkHash)
	if err != nil && !db.IsRecordNotFoundError(err) {
		return nil, jerr.Get("error getting MemoSetName for hash", err)
	}
	if memoSetName != nil {
		name = memoSetName.Name
		nameTx = memoSetName.TxHash
	}
	memoSetPic, err := db.GetPicForPkHash(pkHash)
	if err != nil && !db.IsRecordNotFoundError(err) {
		return nil, jerr.Get("error getting MemoSetPic for hash", err)
	}
	profile := &Profile{
		Name:       name,
		PkHash:     pkHash,
		NameTx:     nameTx,
		SelfPkHash: selfPkHash,
	}
	if memoSetPic != nil {
		profile.Pic = memoSetPic
	}
	if profile.Name == "" {
		profile.Name = fmt.Sprintf("Profile %.16s", profile.GetAddressString())
	}
	memoSetProfile, err := db.GetProfileForPkHash(pkHash)
	if err != nil && !db.IsRecordNotFoundError(err) {
		return nil, jerr.Get("error getting MemoSetProfile for hash", err)
	}
	if memoSetProfile != nil {
		profile.Profile = memoSetProfile.Profile
		profile.ProfileTx = memoSetProfile.TxHash
	}
	return profile, nil
}

func GetBasicProfile(pkHash []byte, selfPkHash []byte) (*Profile, error) {
	pf, err := GetProfile(pkHash, selfPkHash)
	if err != nil {
		return nil, jerr.Get("error getting profile for hash", err)
	}
	err = pf.SetFollowingCount()
	if err != nil {
		return nil, jerr.Get("error setting following count for profile", err)
	}
	err = pf.SetFollowerCount()
	if err != nil {
		return nil, jerr.Get("error setting follower count for profile", err)
	}
	err = pf.SetTopicsFollowingCount()
	if err != nil {
		return nil, jerr.Get("error setting topics following count for profile", err)
	}
	err = pf.SetUserStats()
	if err != nil {
		return nil, jerr.Get("error setting user stats for profile", err)
	}
	if len(selfPkHash) > 0 {
		err = pf.SetReputation()
		if err != nil {
			return nil, jerr.Get("error getting reputation", err)
		}
		err = pf.SetCanFollow()
		if err != nil {
			return nil, jerr.Get("error setting can follow for profile", err)
		}
	}
	return pf, nil
}

func GetProfileAndSetBalances(pkHash []byte, selfPkHash []byte) (*Profile, error) {
	pf, err := GetProfile(pkHash, selfPkHash)
	if err != nil {
		return nil, jerr.Get("error getting profile", err)
	}
	err = pf.SetBalances()
	if err != nil {
		return nil, jerr.Get("error setting balances", err)
	}
	return pf, nil
}

func CanFollow(pkHash []byte, selfPkHash []byte) (bool, error) {
	isFollowing, err := db.IsFollowing(selfPkHash, pkHash)
	if err != nil {
		return false, jerr.Get("error determining is follower from db", err)
	}
	return !isFollowing && bytes.Compare(pkHash, selfPkHash) != 0, nil
}
