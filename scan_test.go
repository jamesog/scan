package main

import (
	"fmt"
	"log"
	"reflect"
	"testing"
)

func createDB(test string) {
	var err error
	err = openDB(fmt.Sprintf("file:%s?mode=memory&cache=shared", test))
	if err != nil {
		log.Fatal(err)
	}
	// TODO(jamesog): Load schema from a file
	schema := []string{
		`CREATE TABLE scan (ip text, port integer, proto text, firstseen datetime, lastseen datetime)`,
		`CREATE TABLE users (email text UNIQUE NOT NULL)`,
		`CREATE TABLE groups (group_name text UNIQUE NOT NULL)`,
		`CREATE TABLE job (id int, cidr text NOT NULL, ports text, proto text, requested_by text, submitted datetime, received datetime, count int)`,
		`CREATE TABLE traceroute (dest text UNIQUE NOT NULL, path text)`,
	}
	for _, stmt := range schema {
		_, err = db.Exec(stmt)
		if err != nil {
			log.Fatal(err)
		}
	}
}

func destroyDB() {
	db.Close()
}

func TestLoadDataWithNoResults(t *testing.T) {
	createDB("TestLoadDataWithNoResults")
	defer destroyDB()
	data, err := loadData(sqlFilter{})
	if err != nil {
		t.Fatalf("error from loadData: %v", err)
	}
	if len(data) != 0 {
		t.Errorf("expected len 0, got %v", len(data))
	}
}

func TestLoadTraceroutesWithNoResults(t *testing.T) {
	createDB("TestLoadTraceroutesWithNoResults")
	defer destroyDB()
	tr, err := loadTraceroutes()
	if err != nil {
		t.Fatal(err)
	}
	if len(tr) != 0 {
		t.Errorf("expected 0 results, got %v", len(tr))
	}
}

func TestLoadJobsWithNoResults(t *testing.T) {
	createDB("TestLoadJobsWithNoResults")
	defer destroyDB()
	data, err := loadJobs(sqlFilter{})
	if err != nil {
		t.Fatalf("error from loadJobs: %v", err)
	}
	if len(data) != 0 {
		t.Errorf("expected len 0, got %v", len(data))
	}
}

func TestSaveData(t *testing.T) {
	createDB("TestSaveData")
	defer destroyDB()
	results := []result{
		{IP: "192.0.2.1", Ports: []port{{Port: 80, Proto: "tcp", Status: "open"}}},
		{IP: "192.0.2.2", Ports: []port{{Port: 80, Proto: "tcp", Status: "open"}}},
		{IP: "192.0.2.3", Ports: []port{{Port: 80, Proto: "tcp", Status: "open"}}},
	}
	count, err := saveData(results)
	if err != nil {
		t.Fatal(err)
	}
	if count != int64(len(results)) {
		t.Errorf("expected count %d, got %d", len(results), count)
	}

}

func TestSaveJob(t *testing.T) {
	createDB("TestSaveJob")
	defer destroyDB()
	id, err := saveJob("192.0.2.0/24", "80,443", "tcp", "sysadmin@example.com")
	if err != nil {
		t.Fatal(err)
	}
	if id != 1 {
		t.Errorf("expected ID 1, got %d", id)
	}
}

func TestResultData(t *testing.T) {
	createDB("TestResultData")
	defer destroyDB()
	want := scanData{0, 0, 0, "0001-01-01 00:00", nil}
	data, err := resultData("", "", "")
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(data, want) {
		t.Errorf("want %+v, got %+v", want, data)
	}
}

func TestUpdateJob(t *testing.T) {
	createDB("TestUpdateJob")
	defer destroyDB()
	id, err := saveJob("192.0.2.0/24", "80,443", "tcp", "sysadmin@example.com")
	if err != nil {
		t.Fatal(err)
	}
	err = updateJob(string(id), 999)
	if err != nil {
		t.Errorf("error updating job: %v", err)
	}
}
