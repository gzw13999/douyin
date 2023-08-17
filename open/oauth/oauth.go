package oauth

import (
	"encoding/json"
	"fmt"
	"net/url"

	"github.com/gzw13999/douyin/open/context"
	"github.com/gzw13999/douyin/open/credential"
	"github.com/gzw13999/douyin/util"
)

const (
	redirectOauthURL      string = "https://open.douyin.com/platform/oauth/connect?client_key=%s&response_type=code&scope=%s&redirect_uri=%s&state=%s"
	silenceOauthURL       string = "https://open.douyin.com/platform/oauth/authorize/v2?client_key=%s&response_type=code&scope=login_id&redirect_uri=%s&state=%s"
	accessTokenURL        string = "https://open.douyin.com/oauth/access_token?client_key=%s&client_secret=%s&code=%s&grant_type=authorization_code"
	refreshAccessTokenURL string = "https://open.douyin.com/oauth/refresh_token?client_key=%s&grant_type=refresh_token&refresh_token=%s"
	//refreshTokenURL       string = "https://open.douyin.com/oauth/oauth/refresh_token?client_key=%s&grant_type=refresh_token&refresh_token=%s"
	renewRefreshTokenURL string = "https://open.douyin.com/oauth/renew_refresh_token?client_key=%s&refresh_token=%s"
	clientTokenURL       string = "https://open.douyin.com/oauth/client_token/?client_key=%s&client_secret=%s&grant_type=client_credential"
)

// Oauth 保存用户授权信息
type Oauth struct {
	*context.Context
}

// NewOauth 实例化授权信息
func NewOauth(context *context.Context) *Oauth {
	auth := new(Oauth)
	auth.Context = context
	return auth
}

// GetRedirectURL 获取授权码的url地址
func (oauth *Oauth) GetRedirectURL(state string) string {
	if oauth.RedirectURL == "" {
		panic("redirect url not set")
	}
	uri := url.QueryEscape(oauth.RedirectURL)
	return fmt.Sprintf(redirectOauthURL, oauth.ClientKey, oauth.Scopes, uri, state)
}

// GetSilenceOauthURL 获取静默授权码的url地址
func (oauth *Oauth) GetSilenceOauthURL(state string) string {
	if oauth.RedirectURL == "" {
		panic("redirect url not set")
	}
	uri := url.QueryEscape(oauth.RedirectURL)
	return fmt.Sprintf(silenceOauthURL, oauth.ClientKey, uri, state)
}

type accessTokenRes struct {
	Message string                 `json:"message"`
	Data    credential.AccessToken `json:"data"`
}

// GetUserAccessToken 通过网页授权的code 换取access_token
func (oauth *Oauth) GetUserAccessToken(code string) (accessToken credential.AccessToken, err error) {
	uri := fmt.Sprintf(accessTokenURL, oauth.ClientKey, oauth.ClientSecret, code)
	var response []byte
	response, err = util.HTTPGet(uri)
	if err != nil {
		return
	}
	var result accessTokenRes
	err = json.Unmarshal(response, &result)
	if err != nil {
		return
	}

	if result.Data.ErrCode != 0 {
		err = fmt.Errorf("GetUserAccessToken error : errcode=%v , errmsg=%v", result.Data.ErrCode, result.Data.ErrMsg)
		return
	}

	err = oauth.SetAccessToken(&result.Data)
	if err != nil {
		return
	}
	accessToken = result.Data
	return
}

// RefreshAccessToken 刷新AccessToken.
// 当access_token过期（过期时间15天）后，可以通过该接口使用refresh_token（过期时间30天）进行刷新
func (oauth *Oauth) RefreshAccessToken(refreshToken string) (accessToken credential.AccessToken, err error) {
	uri := fmt.Sprintf(refreshAccessTokenURL, oauth.ClientKey, refreshToken)
	var response []byte
	response, err = util.HTTPGet(uri)
	if err != nil {
		return
	}
	var result accessTokenRes
	err = json.Unmarshal(response, &result)
	if err != nil {
		return
	}

	if result.Data.ErrCode != 0 {
		err = fmt.Errorf("GetUserAccessToken error : errcode=%v , errmsg=%v", result.Data.ErrCode, result.Data.ErrMsg)
		return
	}

	accessToken = result.Data
	return
}

type refreshTokenRes struct {
	Message string                  `json:"message"`
	Data    credential.RefreshToken `json:"data"`
}

// RenewRefreshToken 刷新refresh_token.
// 前提： client_key需要具备renew_refresh_token这个权限
// 接口说明： 可以通过旧的refresh_token获取新的refresh_token,调用后旧refresh_token会失效，新refresh_token有30天有效期。最多只能获取5次新的refresh_token，5次过后需要用户重新授权。
func (oauth *Oauth) RenewRefreshToken(refreshToken string) (refreshTokenData credential.RefreshToken, err error) {
	uri := fmt.Sprintf(renewRefreshTokenURL, oauth.ClientKey, refreshToken)
	var response []byte
	response, err = util.HTTPGet(uri)
	if err != nil {
		return
	}
	var result refreshTokenRes
	err = json.Unmarshal(response, &result)
	if err != nil {
		return
	}

	if result.Data.ErrCode != 0 {
		err = fmt.Errorf("RenewRefreshToken error : errcode=%v , errmsg=%v", result.Data.ErrCode, result.Data.ErrMsg)
		return
	}
	refreshTokenData = result.Data
	return
}
