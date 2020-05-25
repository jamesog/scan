package sqlite

import "log"

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
