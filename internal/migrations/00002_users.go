package migrations

import (
	"database/sql"

	"github.com/pressly/goose"
)

func init() {
	goose.AddMigration(up00002, down00002)
}

func up00002(tx *sql.Tx) error {
	_, err := tx.Exec(`CREATE TABLE IF NOT EXISTS users (email text)`)
	return err
}

func down00002(tx *sql.Tx) error {
	_, err := tx.Exec(`DROP TABLE users`)
	return err
}
