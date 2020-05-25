package sqlite

import (
	"database/sql"
	"fmt"
	"log"
)

// LoadUsers retrieves all users.
func (db *DB) LoadUsers() ([]string, error) {
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

func (db *DB) LoadGroups() ([]string, error) {
	rows, err := db.Query(`SELECT group_name FROM groups`)
	if err != nil {
		log.Printf("error retrieving groups from database: %v", err)
		return nil, fmt.Errorf("error querying for groups: %w", err)
	}
	defer rows.Close()

	var groups []string

	for rows.Next() {
		var group string
		err := rows.Scan(&group)
		if err != nil {
			return nil, fmt.Errorf("error scanning group: %w", err)
		}
		groups = append(groups, group)
	}
	return groups, nil
}

func (db *DB) UserExists(email string) (bool, error) {
	var x string
	err := db.QueryRow(`SELECT email FROM users WHERE email=?`, email).Scan(&x)
	switch {
	case err != nil && err != sql.ErrNoRows:
		return false, nil
	case err == nil:
		return true, nil
	}

	return false, err
}

// SaveUser stores a new user.
func (db *DB) SaveUser(email string) error {
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

// DeleteUser deletes a user.
func (db *DB) DeleteUser(email string) error {
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
