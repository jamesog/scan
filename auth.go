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

// GroupMember defines whether the user is a member of a group
// It is set by the groups `hasMember` API endpoint
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
func loginHandler(w http.ResponseWriter, r *http.Request) {
	tok := randToken()
	state, err := store.Get(r, "state")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// State only needs to be valid for 5 mins
	state.Options.MaxAge = 300
	state.Values["state"] = tok

	// Store a redirect URL to send the user back to the page they were on
	redir, _ := store.Get(r, "redir")
	redir.Options.MaxAge = 300
	redir.Values["redir"] = r.URL.Query().Get("redir")

	// Save both sessions
	sessions.Save(r, w)

	http.Redirect(w, r, getLoginURL(tok), http.StatusFound)
}

func logoutHandler(w http.ResponseWriter, r *http.Request) {
	session, err := store.Get(r, "user")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	session.Options.MaxAge = -1
	session.Save(r, w)

	// User is logged out. Redirect back to the index page
	http.Redirect(w, r, "/", http.StatusFound)
}

// AuthSession stores the session and OAuth2 client
type AuthSession struct {
	state  *sessions.Session
	user   *sessions.Session
	token  *oauth2.Token
	client *http.Client
}

type googleAPIError struct {
	Error struct {
		Message string `json:"message"`
		Code    int    `json:"code"`
	} `json:"error"`
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
		log.Printf("error retrieving groups from database: %v", err)
		return false, err
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

		if res.StatusCode != http.StatusOK {
			var e googleAPIError
			err := json.Unmarshal(data, &e)
			if err != nil {
				log.Printf("[group %s] error unmarshaling Google API error: %v", group, err)
				continue
			}
			log.Printf("[group %s] error code %d from groups API: %v", group, e.Error.Code, e.Error.Message)
			continue
		}

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
func authHandler(w http.ResponseWriter, r *http.Request) {
	var s AuthSession
	var err error
	s.state, err = store.Get(r, "state")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Check if the user has a valid session
	q := r.URL.Query()
	if s.state.Values["state"] != q.Get("state") {
		http.Error(w, "Invalid session", http.StatusUnauthorized)
		return
	}

	// Attempt to fetch the redirect URI from the store
	uri := "/"
	redir, _ := store.Get(r, "redir")
	if u := redir.Values["redir"]; u != "" {
		uri = u.(string)
	}
	// Destroy the redirect session, it isn't needed any more
	redir.Options.MaxAge = -1
	redir.Save(r, w)

	s.user, err = store.Get(r, "user")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	s.token, err = conf.Exchange(oauth2.NoContext, q.Get("code"))
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	s.client = conf.Client(oauth2.NoContext, s.token)

	var authorised bool

	// Check if the user email is in the individual users list
	// If the individual user is not authorised, check group membership

	user, err := s.userInfo()
	authorised, err = s.validateUser(user)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// The user doesn't have an individual entry, check group membership
	if !authorised {
		authorised, err = s.validateGroupMember(user.Email)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	}

	if authorised {
		// Store the information in the session
		s.user.Values["user"] = user
	} else {
		s.user.AddFlash(fmt.Sprintf("%s is not authorised", user.Email), "unauth_flash")
	}

	s.user.Save(r, w)

	// User is logged in. Redirect back to the index page
	http.Redirect(w, r, uri, http.StatusFound)
}
