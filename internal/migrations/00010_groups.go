package migrations

import (
	"database/sql"
	"fmt"
	"time"

	"github.com/pressly/goose"
)

func init() {
	goose.AddMigration(up00010, down00010)
}

// Add UNIQUE NOT NULL constraint to users email
// Create groups table
func up00010(tx *sql.Tx) error {
	stmts := []string{
		`CREATE TABLE users_migrate (email text UNIQUE NOT NULL)`,
		`INSERT INTO users_migrate SELECT DISTINCT email FROM users`,
		// Preserve the old table just in case
		fmt.Sprintf(`ALTER TABLE users RENAME TO users_00010_%d`, time.Now().Unix()),
		`ALTER TABLE users_migrate RENAME TO users`,

		`CREATE TABLE IF NOT EXISTS groups (group_name text UNIQUE NOT NULL)`,
	}

	for _, stmt := range stmts {
		_, err := tx.Exec(stmt)
		if err != nil {
			return err
		}
	}

	return nil
}

func down00010(tx *sql.Tx) error {
	return nil
}
