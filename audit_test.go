package main

import "testing"

func TestAudit(t *testing.T) {
	createDB("TestAudit")
	defer destroyDB()
	if err := audit("admin@example.com", "add_user", "user1@example.com"); err != nil {
		t.Errorf("couldn't write audit log: %v", err)
	}
}
