package migrations

import (
	"database/sql"

	"github.com/pressly/goose"
)

func init() {
	goose.AddMigration(up00007, down00007)
}

// Add job count column
func up00007(tx *sql.Tx) error {
	_, err := tx.Exec(`ALTER TABLE job ADD COLUMN count int`)
	return err
}

func down00007(tx *sql.Tx) error {
	stmts := []string{
		`CREATE TABLE job_migrate AS SELECT id, cidr, ports, proto, requested_by, submitted, received FROM job`,
		`DROP TABLE job`,
		`ALTER TABLE job_migrate RENAME TO job`,
	}
	for _, stmt := range stmts {
		_, err := tx.Exec(stmt)
		if err != nil {
			return err
		}
	}

	return nil
}
