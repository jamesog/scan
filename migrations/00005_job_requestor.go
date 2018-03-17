package migrations

import (
	"database/sql"
	"fmt"
	"time"

	"github.com/pressly/goose"
)

func init() {
	goose.AddMigration(up00005, down00005)
}

// Add the requested_by column
func up00005(tx *sql.Tx) error {
	stmts := []string{
		`CREATE TABLE job_migrate (id int, cidr text, ports text, proto text, requested_by text, submitted datetime, received datetime)`,
		`INSERT INTO job_migrate (id, cidr, ports, proto, submitted, received) SELECT id, cidr, ports, proto, submitted, received FROM job`,
		// Preserve the old table just in case
		// If an existing database is being migrated there is a potential for
		// data loss because other columns have been added later
		fmt.Sprintf(`ALTER TABLE job RENAME TO job_00005_%d`, time.Now().Unix()),
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

func down00005(tx *sql.Tx) error {
	stmts := []string{
		`CREATE TABLE job_migrate (id int, cidr text, ports text, proto text, submitted datetime, received datetime)`,
		`INSERT INTO job_migrate (id, cidr, ports, proto, submitted, received) SELECT * FROM job`,
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
