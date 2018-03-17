package migrations

import (
	"database/sql"

	"github.com/pressly/goose"
)

func init() {
	goose.AddMigration(up00001, down00001)
}

func up00001(tx *sql.Tx) error {
	_, err := tx.Exec(`CREATE TABLE IF NOT EXISTS scan (ip text, port integer, proto text, firstseen text, lastseen text)`)
	return err
}

func down00001(tx *sql.Tx) error {
	// Can't go down from here!
	return nil
}
