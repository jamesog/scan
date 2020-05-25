package migrations

import (
	"database/sql"

	"github.com/pressly/goose"
)

func init() {
	goose.AddMigration(up00011, down00011)
}

func up00011(tx *sql.Tx) error {
	_, err := tx.Exec(`CREATE TABLE submission (host text NOT NULL, job_id integer, submission_time datetime DEFAULT CURRENT_TIMESTAMP)`)
	return err
}

func down00011(tx *sql.Tx) error {
	_, err := tx.Exec(`DROP TABLE submission`)
	return err
}
