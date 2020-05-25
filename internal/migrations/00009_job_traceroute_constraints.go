package migrations

import (
	"database/sql"
	"fmt"
	"time"

	"github.com/pressly/goose"
)

func init() {
	goose.AddMigration(up00009, down00009)
}

// Add NOT NULL constraint to job cidr
// Add UNIQUE NOT NULL constraint to traceroute dest
func up00009(tx *sql.Tx) error {
	stmts := []string{
		`CREATE TABLE job_migrate (id int, cidr text NOT NULL, ports text, proto text, requested_by text, submitted datetime, received datetime, count int)`,
		`INSERT INTO job_migrate SELECT * FROM job`,
		// Preserve the old table just in case
		// If an existing database is being migrated there is a potential for
		// data loss because columns have been changed later
		fmt.Sprintf(`ALTER TABLE job RENAME TO job_00009_%d`, time.Now().Unix()),
		`ALTER TABLE job_migrate RENAME TO job`,

		`CREATE TABLE traceroute_migrate (dest text UNIQUE NOT NULL, path text)`,
		`INSERT INTO traceroute_migrate SELECT DISTINCT dest, path FROM traceroute`,
		fmt.Sprintf(`ALTER TABLE traceroute RENAME TO traceroute_%d`, time.Now().Unix()),
		`ALTER TABLE traceroute_migrate RENAME TO traceroute`,
	}

	for _, stmt := range stmts {
		_, err := tx.Exec(stmt)
		if err != nil {
			return err
		}
	}
	return nil
}

func down00009(tx *sql.Tx) error {
	_, err := tx.Exec(`DROP TABLE job`)
	return err
}
