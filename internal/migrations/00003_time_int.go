package migrations

import (
	"database/sql"
	"fmt"
	"time"

	"github.com/pressly/goose"
)

func init() {
	goose.AddMigration(up00003, down00003)
}

// Alter the firstseen and lastseen columns from text to int
func up00003(tx *sql.Tx) error {
	stmts := []string{
		`CREATE TABLE scan_migrate (ip text, port integer, proto text, firstseen int, lastseen int)`,
		`INSERT INTO scan_migrate SELECT ip, port, proto, strftime('%s', firstseen), strftime('%s', lastseen) FROM scan`,
		// Preserve the old table just in case
		// If an existing database is being migrated there is a potential for
		// data loss because columns have been changed later
		fmt.Sprintf(`ALTER TABLE scan RENAME TO scan_00003_%d`, time.Now().Unix()),
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

func down00003(tx *sql.Tx) error {
	stmts := []string{
		`CREATE TABLE scan_migrate (ip text, port integer, proto text, firstseen text, lastseen text)`,
		`INSERT INTO scan_migrate SELECT ip, port, proto strftime('%Y-%m-%d %H:%M', firstseen), strftime('%Y-%m-%d %H:%M', lastseen) FROM scan`,
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
