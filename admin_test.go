package main

import (
	"net/url"
	"testing"
)

func TestAdminFormProcess(t *testing.T) {
	createDB("TestAdminFormProcess")
	defer destroyDB()

	f := url.Values{}
	user := User{Email: "admin@example.com"}
	users, err := loadUsers()
	if err != nil {
		t.Fatalf("couldn't fetch from users table: %v", err)
	}

	t.Run("AddNewUser", func(t *testing.T) {
		f.Set("add_email", "user1@example.com")
		err := adminFormProcess(f, user, users)
		if err != nil {
			t.Errorf("expected no error; got %v", err)
		}
	})

	t.Run("AddExistingUser", func(t *testing.T) {
		users, err = loadUsers()
		if err != nil {
			t.Fatalf("couldn't fetch from users table: %v", err)
		}
		err := adminFormProcess(f, user, users)
		if err != errUserExists {
			t.Errorf("expected UserExistsError; got %v", err)
		}
	})

	f.Del("add_email")

	t.Run("DeleteExistingUser", func(t *testing.T) {
		f.Set("delete_email", "user1@example.com")
		err := adminFormProcess(f, user, users)
		if err != nil {
			t.Errorf("expected no error; got %v", err)
		}
	})

	t.Run("DeleteSelf", func(t *testing.T) {
		f.Set("delete_email", "user1@example.com")
		user.Email = "user1@example.com"
		err := adminFormProcess(f, user, users)
		if err != errSelfDeletion {
			t.Fatalf("expected SelfDeletionError; got %v", err)
		}
	})
}
