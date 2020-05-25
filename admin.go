package main

import (
	"errors"
	"net/http"
	"net/url"
	"strings"
)

type userData struct {
	indexData
	Users *[]string
}

func (u *userData) AddError(err string) {
	u.Errors = append(u.Errors, err)
}

// Handler for GET and POST /admin
func (app *App) adminHandler(w http.ResponseWriter, r *http.Request) {
	if authDisabled {
		http.Error(w, "Admin interface not available when authentication is disabled.", http.StatusNotImplemented)
		return
	}

	var user User
	session, err := store.Get(r, "user")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if _, ok := session.Values["user"]; !ok {
		data := indexData{URI: r.RequestURI}
		if flash := session.Flashes("unauth_flash"); len(flash) > 0 {
			data.NotAuth = flash[0].(string)
			w.WriteHeader(http.StatusUnauthorized)
			session.Save(r, w)
		}
		tmpl.ExecuteTemplate(w, "index", data)
		return
	}
	v := session.Values["user"]
	switch v := v.(type) {
	case string:
		user.Email = v
	case User:
		user = v
	}

	users, err := app.db.LoadUsers()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	data := userData{
		indexData: indexData{Authenticated: true, User: user},
		Users:     &users,
	}

	// Handle deleting and adding users
	if r.Method == "POST" {
		err := r.ParseForm()
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		f := r.Form
		err = app.adminFormProcess(f, user, users)
		switch {
		case err == errUserExists:
			data.AddError(userExists)
			w.WriteHeader(http.StatusBadRequest)
		case err == errSelfDeletion:
			data.AddError(selfDeletion)
			w.WriteHeader(http.StatusBadRequest)
		case err != nil:
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		case err == nil:
			// Reload the list of users
			users, err = app.db.LoadUsers()
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
		}
	}

	tmpl.ExecuteTemplate(w, "admin", data)
}

var (
	userExists      = "User already exists"
	selfDeletion    = "You can't delete yourself"
	errUserExists   = errors.New(strings.ToLower(userExists))
	errSelfDeletion = errors.New(strings.ToLower(selfDeletion))
)

func (app *App) adminFormProcess(f url.Values, user User, users []string) error {
	if add := f.Get("add_email"); add != "" {
		// Check if the address already exists as a user
		for _, u := range users {
			if u == add {
				return errUserExists
			}
		}
		if err := app.db.SaveUser(add); err != nil {
			return err
		}
		app.audit(user.Email, "add_user", add)
	}

	if delete := f.Get("delete_email"); delete != "" {
		// Ensure the user isn't trying to delete themselves
		if user.Email == delete {
			return errSelfDeletion
		}
		if err := app.db.DeleteUser(delete); err != nil {
			return err
		}
		app.audit(user.Email, "delete_user", delete)
	}

	return nil
}
