package migrations

import (
	"database/sql"
	"fmt"
	"time"

	"github.com/pressly/goose"
)

func init() {
	goose.AddMigration(up00006, down00006)
}

// Change firstseen and lastseen from int to datetime
func up00006(tx *sql.Tx) error {
	stmts := []string{
		`CREATE TABLE scan_migrate (ip text, port integer, proto text, firstseen datetime, lastseen datetime)`,
		`INSERT INTO scan_migrate SELECT ip, port, proto, datetime(firstseen), datetime(lastseen) FROM scan`,
		// Preserve the old table just in case
		// If an existing database is being migrated there is a potential for
		// data loss because columns have been changed later
		fmt.Sprintf(`ALTER TABLE scan RENAME TO scan_00006_%d`, time.Now().Unix()),
		`ALTER TABLE scan_migrate RENAME TO scan`,
	}
	for _, stmt := range stmts {
		_, err := tx.Exec(stmt)
		if err != nil {
			return err
		}
	}

	return nil
}

func down00006(tx *sql.Tx) error {
	stmts := []string{
		`CREATE TABLE scan_migrate (ip text, port integer, proto text, firstseen int, lastseen int)`,
		`INSERT INTO scan_migrate SELECT ip, port, proto strftime('%s', firstseen), strftime('%s', lastseen) FROM scan`,
		`DROP TABLE scan`,
		`ALTER TABLE scan_migrate RENAME TO scan`,
	}
	for _, stmt := range stmts {
		_, err := tx.Exec(stmt)
		if err != nil {
			return err
		}
	}

	return nil
}
