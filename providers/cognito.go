package providers

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/bitly/go-simplejson"
	"github.com/pusher/oauth2_proxy/api"
	"github.com/pusher/oauth2_proxy/pkg/apis/sessions"
)

type CognitoProvider struct {
	*ProviderData
	Domain string
	Region string
	Group  string
}

func NewCognitoProvider(p *ProviderData) *CognitoProvider {
	p.ProviderName = "Cognito"
	if p.Scope == "" {
		p.Scope = "openid"
	}
	log.Printf("SCOPES: %s", p.Scope)
	return &CognitoProvider{ProviderData: p}
}

func (p *CognitoProvider) Configure(domain string, region string, group string) {
	p.Domain = domain
	p.Region = region
	p.Group = group
	if region == "" {
		p.Region = "us-east-1"
	}
	//p.ProfileURL = &url.URL{Scheme: "https", Host: "localhost"}
	if p.ProfileURL == nil || p.ProfileURL.String() == "" {
		p.ProfileURL = &url.URL{
			Scheme: "https",
			Host:   p.Domain + ".auth." + p.Region + ".amazoncognito.com",
			Path:   "/oauth2/userInfo",
		}
	}

	if p.LoginURL == nil || p.LoginURL.String() == "" {
		p.LoginURL = &url.URL{
			Scheme: "https",
			Host:   p.Domain + ".auth." + p.Region + ".amazoncognito.com",
			Path:   "/oauth2/authorize"}
	}
	if p.RedeemURL == nil || p.RedeemURL.String() == "" {
		p.RedeemURL = &url.URL{
			Scheme: "https",
			Host:   p.Domain + ".auth." + p.Region + ".amazoncognito.com",
			Path:   "/oauth2/token",
		}
	}
}

//TODO: This, getEmailFromJSON, also exists in Azure. we need to move it to another module, for now
// renaming it
func getEmailFromJSON2(json *simplejson.Json) (string, error) {
	var email string
	var err error

	email, err = json.Get("mail").String()

	if err != nil || email == "" {
		otherMails, otherMailsErr := json.Get("otherMails").Array()
		if len(otherMails) > 0 {
			email = otherMails[0].(string)
		}
		err = otherMailsErr
	}

	return email, err
}

func (p *CognitoProvider) GetEmailAddress(s *sessions.SessionState) (string, error) {
	var email string
	var err error

	if s.AccessToken == "" {
		return "", errors.New("missing access token")
	}

	req, err := http.NewRequest("GET", p.ProfileURL.String(), nil)
	if err != nil {
		return "", err
	}
	req.Header = getCognitoHeader(s.AccessToken)

	log.Printf("GetEmailAddress Request is %s", req)
	log.Printf("GetEmailAddress Session is %s", s)
	json, err := api.Request(req)

	if err != nil {
		return "", err
	}

	log.Printf("JSON    :    %s", json)
	email, err = getEmailFromJSON2(json)

	if err == nil && email != "" {
		return email, err
	}

	email, err = json.Get("email").String()

	if err != nil {
		log.Printf("failed making request %s", err)
		return "", err
	}

	if email == "" {
		log.Printf("failed to get email address")
		return "", err
	}

	return email, err
}
func getCognitoHeader(access_token string) http.Header {
	header := make(http.Header)
	header.Set("Authorization", fmt.Sprintf("Bearer %s", access_token))
	return header
}

func (p *CognitoProvider) Redeem(redirectURL, code string) (s *sessions.SessionState, err error) {
	if code == "" {
		err = errors.New("missing code")
		return
	}
	log.Printf("REDEEM %s", p.Scope)
	p.Scope = "openid"
	params := url.Values{}
	params.Add("redirect_uri", redirectURL)
	params.Add("client_id", p.ClientID)
	params.Add("client_secret", p.ClientSecret)
	params.Add("code", code)
	params.Add("grant_type", "authorization_code")
	var req *http.Request
	req, err = http.NewRequest("POST", p.RedeemURL.String(), bytes.NewBufferString(params.Encode()))
	if err != nil {
		return
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	log.Printf("REDEEM REQ: %s", req)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return
	}
	log.Printf("REDEEM RESP: %s", resp)

	var body []byte
	body, err = ioutil.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		return
	}
	log.Printf("REDEEM BODY: %s", body)

	if resp.StatusCode != 200 {
		err = fmt.Errorf("got %d from %q %s", resp.StatusCode, p.RedeemURL.String(), body)
		return
	}

	var jsonResponse struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
		ExpiresIn    int64  `json:"expires_in"`
		IdToken      string `json:"id_token"`
	}
	err = json.Unmarshal(body, &jsonResponse)
	if err != nil {
		return
	}
	var email string
	email, err = cognitoEmailFromIdToken(jsonResponse.IdToken)
	if err != nil {
		return
	}

	s = &sessions.SessionState{
		AccessToken:  jsonResponse.AccessToken,
		ExpiresOn:    time.Now().Add(time.Duration(jsonResponse.ExpiresIn) * time.Second).Truncate(time.Second),
		RefreshToken: jsonResponse.RefreshToken,
		Email:        email,
	}

	var req2 *http.Request
	var err2 error
	req2, err2 = http.NewRequest("GET", p.ProfileURL.String(), nil)
	req2.Header = getCognitoHeader(s.AccessToken)
	//req2.Header.Set("Authorization", fmt.Sprintf("Bearer %s", s.AccessToken))

	if err2 != nil {
		return
	}

	log.Printf("USERINFO Request is %s", req2)
	resp2, err := http.DefaultClient.Do(req2)
	if err != nil {
		return
	}
	log.Printf("USERINFO RESP: %s", resp2)

	var body2 []byte
	body2, err = ioutil.ReadAll(resp2.Body)
	resp2.Body.Close()
	if err != nil {
		return
	}
	log.Printf("REDEEM BODY: %s", body2)
	var groups []string
	groups, err = cognitoGroupFromIdToken(jsonResponse.IdToken)
	if err != nil {
		return
	}
	log.Printf("GROUPS %s", groups)
	//var group string
	//group = "TEST"
	if !userInGroup2(p.Group, jsonResponse.IdToken) && p.Group != "" {
		log.Printf("Not a Member!!!! %s", s)
		s.AccessToken = ""
		s.Email = ""
		s.ExpiresOn = time.Now()
		log.Printf("Not a Member!!!! %s", s)
	}
	return
}

//TODO: userInGroup also exists in google.go, remaning
func userInGroup2(groupName string, idToken string) bool {
	var err error
	var groups []string
	log.Printf("DATA:   %s %s ", groupName, idToken)
	groups, err = cognitoGroupFromIdToken(idToken)
	log.Printf("Data 2: %s", groups)
	for _, group := range groups {
		log.Printf("GROUPS MEMBER: %s %s", groupName, group)
		if groupName == group {
			return true
		}
	}
	log.Printf("%s", err)
	return false
}

/*
func userInGroup(service *admin.Service, groups []string, email string) bool {
	user, err := fetchUser(service, email)
	if err != nil {
		log.Printf("error fetching user: %v", err)
		return false
	}
	id := user.Id
	custID := user.CustomerId

	for _, group := range groups {
		members, err := fetchGroupMembers(service, group)
		if err != nil {
			if err, ok := err.(*googleapi.Error); ok && err.Code == 404 {
				log.Printf("error fetching members for group %s: group does not exist", group)
			} else {
				log.Printf("error fetching group members: %v", err)
				return false
			}
		}

		for _, member := range members {
			switch member.Type {
			case "CUSTOMER":
				if member.Id == custID {
					return true
				}
			case "USER":
				if member.Id == id {
					return true
				}
			}
		}
	}
	return false
}
*/
func cognitoGroupFromIdToken(idToken string) ([]string, error) {
	var x []string
	jwt := strings.Split(idToken, ".")
	jwtData := strings.TrimSuffix(jwt[1], "=")
	b, err := base64.RawURLEncoding.DecodeString(jwtData)
	if err != nil {
		return x, err
	}
	var groups struct {
		Groups []string `json:"cognito:groups"`
	}
	err = json.Unmarshal(b, &groups)
	if err != nil {
		return x, err
	}
	if groups.Groups[0] == "" {
		return x, errors.New("missing groups")
	}
	return groups.Groups, nil
}
func cognitoEmailFromIdToken(idToken string) (string, error) {

	// id_token is a base64 encode ID token payload
	// https://developers.google.com/accounts/docs/OAuth2Login#obtainuserinfo
	jwt := strings.Split(idToken, ".")
	jwtData := strings.TrimSuffix(jwt[1], "=")
	b, err := base64.RawURLEncoding.DecodeString(jwtData)
	if err != nil {
		return "", err
	}
	log.Printf("JWT = %s", b)
	var email struct {
		Email         string `json:"email"`
		EmailVerified bool   `json:"email_verified"`
	}
	err = json.Unmarshal(b, &email)
	if err != nil {
		return "", err
	}
	if email.Email == "" {
		return "", errors.New("missing email")
	}
	// if !email.EmailVerified {
	//	return "", fmt.Errorf("email %s not listed as verified", email.Email)
	//}
	return email.Email, nil
}
