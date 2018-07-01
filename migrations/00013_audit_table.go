package migrations

import (
	"database/sql"

	"github.com/pressly/goose"
)

func init() {
	goose.AddMigration(up00013, down00013)
}

func up00013(tx *sql.Tx) error {
	_, err := tx.Exec(`CREATE TABLE IF NOT EXISTS audit (time datetime NOT NULL, user text NOT NULL, action text NOT NULL, info text)`)
	return err
}

func down00013(tx *sql.Tx) error {
	_, err := tx.Exec(`DROP TABLE IF EXISTS audit`)
	return err
}
