package main

import (
	"errors"
	"log"
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
func adminHandler(w http.ResponseWriter, r *http.Request) {
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
	switch v.(type) {
	case string:
		user.Email = v.(string)
	case User:
		user = v.(User)
	}

	users, err := loadUsers()
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
		err = adminFormProcess(f, user, users)
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
			users, err = loadUsers()
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

func adminFormProcess(f url.Values, user User, users []string) error {
	if add := f.Get("add_email"); add != "" {
		// Check if the address already exists as a user
		for _, u := range users {
			if u == add {
				return errUserExists
			}
		}
		if err := saveUser(add); err != nil {
			return err
		}
		audit(user.Email, "add_user", add)
	}

	if delete := f.Get("delete_email"); delete != "" {
		// Ensure the user isn't trying to delete themselves
		if user.Email == delete {
			return errSelfDeletion
		}
		if err := deleteUser(delete); err != nil {
			return err
		}
		audit(user.Email, "delete_user", delete)
	}

	return nil
}

func loadUsers() ([]string, error) {
	rows, err := db.Query(`SELECT * FROM users ORDER BY email`)
	if err != nil {
		log.Printf("error loading users: %v\n", err)
		return []string{}, err
	}
	defer rows.Close()

	var users []string
	var email string

	for rows.Next() {
		err := rows.Scan(&email)
		if err != nil {
			log.Println("loadUsers: error scanning table:", err)
			return []string{}, err
		}
		users = append(users, email)
	}

	return users, nil
}

func saveUser(email string) error {
	txn, err := db.Begin()
	if err != nil {
		return err
	}

	qry := `INSERT INTO users (email) VALUES (?)`
	_, err = txn.Exec(qry, email)
	if err != nil {
		txn.Rollback()
		return err
	}

	err = txn.Commit()
	if err != nil {
		return err
	}

	return nil
}

func deleteUser(email string) error {
	txn, err := db.Begin()
	if err != nil {
		return err
	}

	qry := `DELETE FROM users WHERE email = ?`
	_, err = txn.Exec(qry, email)
	if err != nil {
		txn.Rollback()
		return err
	}

	err = txn.Commit()
	if err != nil {
		return err
	}

	return nil
}
