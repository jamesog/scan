package main

import "testing"

func TestAudit(t *testing.T) {
	db := createDB("TestAudit")
	defer db.Close()
	app := &App{db: db}
	if err := app.audit("admin@example.com", "add_user", "user1@example.com"); err != nil {
		t.Errorf("couldn't write audit log: %v", err)
	}
}
