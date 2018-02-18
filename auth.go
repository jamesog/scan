package main

import (
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"encoding/gob"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"path/filepath"

	"github.com/gorilla/securecookie"
	"github.com/gorilla/sessions"
	"github.com/labstack/echo"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
)

var conf *oauth2.Config

var store *sessions.CookieStore

// User is a Google user
type User struct {
	Name       string `json:"name"`
	GivenName  string `json:"given_name"`
	FamilyName string `json:"family_name"`
	Email      string `json:"email"`
	Picture    string `json:"picture"`
}

type GroupMember struct {
	IsMember bool `json:"isMember"`
}

func init() {
	gob.Register(User{})
}

func oauthConfig() {
	keyFile := filepath.Join(dataDir, ".cookie_key")
	if key, err := ioutil.ReadFile(keyFile); err == nil {
		store = sessions.NewCookieStore(key)
	} else {
		// TODO(jamesog): Add a second parameter for encryption
		// This makes it more complicated to write to the cache file
		// It should probably be saved in the database instead
		key := securecookie.GenerateRandomKey(64)
		err := ioutil.WriteFile(keyFile, key, 0600)
		if err != nil {
			log.Fatal(err)
		}
		store = sessions.NewCookieStore(key)
	}

	f, err := ioutil.ReadFile(credsFile)
	if err != nil {
		log.Fatalf("couldn't read credentials file: %s", err)
	}

	scopes := []string{
		"https://www.googleapis.com/auth/userinfo.email",
		"https://www.googleapis.com/auth/userinfo.profile",
		"https://www.googleapis.com/auth/admin.directory.group.member.readonly",
	}
	conf, err = google.ConfigFromJSON(f, scopes...)
	if err != nil {
		log.Fatalf("couldn't parse OAuth2 config: %s", err)
	}
}

func getLoginURL(state string) string {
	return conf.AuthCodeURL(state)
}

func randToken() string {
	b := make([]byte, 32)
	rand.Read(b)
	return base64.StdEncoding.EncodeToString(b)
}

// loginHandler is just a redirect to the Google login page
func loginHandler(c echo.Context) error {
	state := randToken()
	session, err := store.Get(c.Request(), "state")
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, err)
	}

	session.Values["state"] = state
	session.Save(c.Request(), c.Response().Writer)
	return c.Redirect(http.StatusFound, getLoginURL(state))
}

func logoutHandler(c echo.Context) error {
	session, err := store.Get(c.Request(), "user")
	if err != nil {
		return c.String(http.StatusInternalServerError, err.Error())
	}
	session.Options.MaxAge = -1
	session.Save(c.Request(), c.Response().Writer)

	// User is logged out. Redirect back to the index page
	return c.Redirect(http.StatusFound, "/")
}

// AuthSession stores the session and OAuth2 client
type AuthSession struct {
	state  *sessions.Session
	user   *sessions.Session
	token  *oauth2.Token
	client *http.Client
}

// userInfo fetches the user profile info from the Google API
func (s AuthSession) userInfo() (*User, error) {
	// Retrieve the logged in user's information
	res, err := s.client.Get("https://www.googleapis.com/oauth2/v3/userinfo")
	if err != nil {
		return nil, err
	}

	defer res.Body.Close()

	data, _ := ioutil.ReadAll(res.Body)

	// Unmarshal the user data
	var user User
	err = json.Unmarshal(data, &user)
	if err != nil {
		return nil, err
	}

	return &user, nil
}

// validateUser looks up the user's email address in the database and returns
// true if they exist
func (s AuthSession) validateUser(user *User) (bool, error) {

	// x is a dummy variable to scan in to - we don't actually care about the
	// result, just that a row was returned
	var x string
	err := db.QueryRow(`SELECT email FROM users WHERE email=?`, user.Email).Scan(&x)
	switch {
	case err != nil && err != sql.ErrNoRows:
		return false, err
	case err == nil:
		return true, nil
	}

	return false, nil
}

// validateGroupMember looks up all group names in the database and returns
// true if the user is a member of any of the groups
func (s AuthSession) validateGroupMember(email string) (bool, error) {
	var group string

	url := "https://www.googleapis.com/admin/directory/v1/groups/%s/hasMember/%s"

	rows, err := db.Query(`SELECT group_name FROM groups`)
	if err != nil {
	}
	defer rows.Close()

	for rows.Next() {
		err := rows.Scan(&group)
		if err != nil {
			continue
		}

		res, err := s.client.Get(fmt.Sprintf(url, group, email))
		if err != nil {
			log.Printf("error retrieving user %s for group %s: %v", email, group, err)
			continue
		}
		defer res.Body.Close()

		data, _ := ioutil.ReadAll(res.Body)
		var gm GroupMember
		err = json.Unmarshal(data, &gm)
		if err != nil {
			return false, err
		}

		if gm.IsMember {
			return true, nil
		}
	}

	return false, nil
}

// authHandler receives the login information from Google and checks if the
// email address is authorized
func authHandler(c echo.Context) error {
	var s AuthSession
	var err error
	s.state, err = store.Get(c.Request(), "state")
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, err)
	}

	// Check if the user has a valid session
	if s.state.Values["state"] != c.QueryParam("state") {
		return c.String(http.StatusUnauthorized, "Invalid session")
	}

	s.user, err = store.Get(c.Request(), "user")
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, err)
	}

	s.token, err = conf.Exchange(oauth2.NoContext, c.QueryParam("code"))
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, err)
	}

	s.client = conf.Client(oauth2.NoContext, s.token)

	var authorised bool

	// Check if the user email is in the individual users list
	// If the individual user is not authorised, check group membership

	user, err := s.userInfo()
	authorised, err = s.validateUser(user)
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, err)
	}

	// The user doesn't have an individual entry, check group membership
	if !authorised {
		authorised, err = s.validateGroupMember(user.Email)
		if err != nil {
			return echo.NewHTTPError(http.StatusInternalServerError, err)
		}
	}

	if !authorised {
		return c.String(http.StatusUnauthorized, fmt.Sprintf("%s is not authorized", user.Email))
	}

	// Store the email in the session
	s.user.Values["user"] = user
	s.user.Save(c.Request(), c.Response().Writer)

	// User is logged in. Redirect back to the index page
	return c.Redirect(http.StatusFound, "/")
}
