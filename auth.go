package main

import (
	"crypto/rand"
	"database/sql"
	"encoding/base64"
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

	conf, err = google.ConfigFromJSON(f, "https://www.googleapis.com/auth/userinfo.email")
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

// authHandler receives the login information from Google and checks if the
// email address is authorized
func authHandler(c echo.Context) error {
	session, err := store.Get(c.Request(), "state")
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, err)
	}

	// Check if the user has a valid session
	if session.Values["state"] != c.QueryParam("state") {
		return c.String(http.StatusUnauthorized, "Invalid session")
	}

	tok, err := conf.Exchange(oauth2.NoContext, c.QueryParam("code"))
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, err)
	}

	// Retrieve the logged in user's information
	client := conf.Client(oauth2.NoContext, tok)
	res, err := client.Get("https://www.googleapis.com/oauth2/v3/userinfo")
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, err)
	}

	defer res.Body.Close()

	data, _ := ioutil.ReadAll(res.Body)

	session, err = store.Get(c.Request(), "user")
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, err)
	}

	// Unmarshal the user data
	var user User
	err = json.Unmarshal(data, &user)
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, err)
	}

	// Look up the user's email address in the database

	// Dummy variable to scan in to
	var x string
	err = db.QueryRow(`SELECT email FROM users WHERE email=?`, user.Email).Scan(&x)
	switch {
	case err == sql.ErrNoRows:
		return c.String(http.StatusUnauthorized, fmt.Sprintf("%s is not authorized", user.Email))
	case err != nil:
		return c.String(http.StatusInternalServerError, err.Error())
	}

	// Store the email in the session
	session.Values["user"] = user.Email
	session.Save(c.Request(), c.Response().Writer)

	// User is logged in. Redirect back to the index page
	return c.Redirect(http.StatusFound, "/")
}
