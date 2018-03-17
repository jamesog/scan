package migrations

import (
	"database/sql"

	"github.com/pressly/goose"
)

func init() {
	goose.AddMigration(up00008, down00008)
}

// Add traceroute table
func up00008(tx *sql.Tx) error {
	_, err := tx.Exec(`CREATE TABLE IF NOT EXISTS traceroute (dest text, path text)`)
	return err
}

func down00008(tx *sql.Tx) error {
	_, err := tx.Exec(`DROP TABLE job`)
	return err
}
