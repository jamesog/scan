package main

import "time"

// audit logs events to the audit table
func audit(user, event, info string) error {
	txn, err := db.Begin()
	if err != nil {
		return err
	}

	qry := `INSERT INTO audit (time, user, action, info) VALUES (?, ?, ?, ?)`
	_, err = txn.Exec(qry, time.Now(), user, event, info)
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
