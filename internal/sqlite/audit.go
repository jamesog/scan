package sqlite

import "time"

func (db *DB) SaveAudit(ts time.Time, user, event, info string) error {
	txn, err := db.Begin()
	if err != nil {
		return err
	}

	qry := `INSERT INTO audit (time, user, action, info) VALUES (?, ?, ?, ?)`
	_, err = txn.Exec(qry, ts, user, event, info)
	if err != nil {
		txn.Rollback()
		return err
	}

	return txn.Commit()
}
