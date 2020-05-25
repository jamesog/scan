package migrations

import (
	"database/sql"

	"github.com/pressly/goose"
)

func init() {
	goose.AddMigration(up00004, down00004)
}

func up00004(tx *sql.Tx) error {
	_, err := tx.Exec(`CREATE TABLE IF NOT EXISTS job (id int, cidr text, ports text, proto text, submitted datetime, received datetime)`)
	return err
}

func down00004(tx *sql.Tx) error {
	_, err := tx.Exec(`DROP TABLE job`)
	return err
}
