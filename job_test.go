package main

import (
	"bytes"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"

	"github.com/jamesog/scan/internal/sqlite"
)

func TestLoadJobsWithNoResults(t *testing.T) {
	db := createDB("TestLoadJobsWithNoResults")
	defer db.Close()
	data, err := db.LoadJobs(sqlite.SQLFilter{})
	if err != nil {
		t.Fatalf("error from loadJobs: %v", err)
	}
	if len(data) != 0 {
		t.Errorf("expected len 0, got %v", len(data))
	}
}

func TestSaveJob(t *testing.T) {
	db := createDB("TestSaveJob")
	defer db.Close()
	id, err := db.SaveJob("192.0.2.0/24", "80,443", "tcp", "sysadmin@example.com")
	if err != nil {
		t.Fatal(err)
	}
	if id != 1 {
		t.Errorf("expected ID 1, got %d", id)
	}
}

func TestUpdateJob(t *testing.T) {
	db := createDB("TestUpdateJob")
	defer db.Close()
	id, err := db.SaveJob("192.0.2.0/24", "80,443", "tcp", "sysadmin@example.com")
	if err != nil {
		t.Fatal(err)
	}
	err = db.UpdateJob(strconv.FormatInt(id, 10), 999)
	if err != nil {
		t.Errorf("error updating job: %v", err)
	}
}

func TestJobHandler(t *testing.T) {
	db := createDB("TestJobHandler")
	defer db.Close()
	app := App{db: db}

	r := httptest.NewRequest("GET", "/job", nil)
	w := httptest.NewRecorder()
	app.newJob(w, r)

	resp := w.Result()
	body, _ := ioutil.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected status 200, got %v: %s", resp.StatusCode, body)
	}

	v := url.Values{}
	v.Set("cidr", "192.0.2.0/24")
	v.Set("ports", "1-1024")
	v.Set("proto", "tcp")

	r = httptest.NewRequest("POST", "/job", strings.NewReader(v.Encode()))
	w = httptest.NewRecorder()
	app.newJob(w, r)

	resp = w.Result()
	body, _ = ioutil.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected status 200, got %v: %s", resp.StatusCode, body)
	}
}

func TestJobsHandler(t *testing.T) {
	db := createDB("TestJobsHandler")
	defer db.Close()
	app := App{db: db}

	r := httptest.NewRequest("GET", "/jobs", nil)
	w := httptest.NewRecorder()
	app.jobs(w, r)

	resp := w.Result()
	body, _ := ioutil.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected status 200, got %v: %s", resp.StatusCode, body)
	}
	ct := resp.Header.Get("Content-Type")
	if ct != "application/json" {
		t.Errorf("expected Content-Type: %s, got %v", "application/json", ct)
	}
}

func TestJobResultsHandler(t *testing.T) {
	db := createDB("TestJobResultsHandler")
	defer db.Close()
	app := App{db: db}

	data := bytes.NewBuffer([]byte(`[{"ip":"192.0.2.1","ports":[{"port":80,"proto":"tcp","status":"open","reason":"syn-ack","ttl":57}]}]`))

	mux := app.setupRouter()
	ts := httptest.NewServer(mux)
	defer ts.Close()

	// We need to save some job data before trying to submit any
	app.db.SaveJob("192.0.2.1", "80", "tcp", "testuser@example.com")

	req, err := http.NewRequest("PUT", ts.URL+"/results/1", data)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected status 200, got %v", resp.StatusCode)
	}

	// Do it again - submitting the same job should be an error
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("expected status 400, got %v", resp.StatusCode)
	}
}
