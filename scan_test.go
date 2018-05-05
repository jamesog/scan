package main

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"log"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"strings"
	"testing"
	"time"
)

func createDB(test string) {
	var err error
	err = openDB(fmt.Sprintf("file:%s?mode=memory&cache=shared", test))
	if err != nil {
		log.Fatal(err)
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
	count, err := saveData(results, time.Now().UTC())
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
	want := scanData{Total: 0, Latest: 0, New: 0, LastSeen: "0001-01-01 00:00", Results: nil}
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

// TestIndexHandlerWithoutAuth tests fetching the index page with
// authentication disabled
func TestIndexHandlerWithoutAuth(t *testing.T) {
	createDB("TestIndexHandlerWithoutAuth")
	defer destroyDB()

	// We can't go through the OAuth2 login flow in tests
	authDisabled = true

	setupTemplates()

	r := httptest.NewRequest("GET", "/", nil)
	w := httptest.NewRecorder()
	index(w, r)

	resp := w.Result()
	body, _ := ioutil.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected status 200, got %v: %s", resp.StatusCode, body)
	}
}

// TestIPsHandler tests that we get expected JSON data
func TestIPsHandler(t *testing.T) {
	createDB("TestIPsHandler")
	defer destroyDB()

	r := httptest.NewRequest("GET", "/ips.json", nil)
	w := httptest.NewRecorder()
	ips(w, r)

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

func TestJobHandler(t *testing.T) {
	createDB("TestJobHandler")
	defer destroyDB()

	r := httptest.NewRequest("GET", "/job", nil)
	w := httptest.NewRecorder()
	newJob(w, r)

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
	newJob(w, r)

	resp = w.Result()
	body, _ = ioutil.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected status 200, got %v: %s", resp.StatusCode, body)
	}
}

func TestJobsHandler(t *testing.T) {
	createDB("TestJobsHandler")
	defer destroyDB()

	r := httptest.NewRequest("GET", "/jobs", nil)
	w := httptest.NewRecorder()
	jobs(w, r)

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

func TestResultsHandler(t *testing.T) {
	createDB("TestResultsHandler")
	defer destroyDB()

	data := bytes.NewBuffer([]byte(`[{"ip":"192.0.2.1","ports":[{"port":80,"proto":"tcp","status":"open","reason":"syn-ack","ttl":57}]}]`))

	r := httptest.NewRequest("POST", "/results", data)
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	recvResults(w, r)

	resp := w.Result()
	body, _ := ioutil.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected status 200, got %v: %s", resp.StatusCode, body)
	}

	filter := sqlFilter{Where: []string{"ip = ?"}, Values: []interface{}{"192.0.2.1"}}
	results, err := loadData(filter)
	if err != nil {
		t.Errorf("couldn't retrieve results from database: %v", err)
	}
	if len(results) > 1 {
		t.Errorf("expected 1 result, got %d", len(results))
	}
	if results[0].IP != "192.0.2.1" {
		t.Errorf("expected IP %s, got %v", "192.0.2.1", results[0].IP)
	}
	if results[0].Port != 80 {
		t.Errorf("expected port %d, got %v", 80, results[0].Port)
	}
	if results[0].Proto != "tcp" {
		t.Errorf("expected proto %s, got %v", "tcp", results[0].Proto)
	}

	// TODO(jamesog): We should test sending the same data to test the update
	// path in saveData() but this is currently difficult due to the way
	// times are stored in the database (as strings instead of raw values) -
	// it would require sleeping for some time, which isn't good.
	// ls := results[0].LastSeen
	// time.Sleep(70 * time.Second)
	// recvResults(w, r)

	// resp = w.Result()
	// body, _ = ioutil.ReadAll(resp.Body)
	// if resp.StatusCode != http.StatusOK {
	// 	t.Errorf("expected status 200, got %v: %s", resp.StatusCode, body)
	// }

	// results, _ = loadData(filter)
	// if results[0].LastSeen == ls {
	// 	t.Errorf("lastseen did not update, %v, %v", ls, results[0].LastSeen)
	// }
}

func TestJobResultsHandler(t *testing.T) {
	createDB("TestJobResultsHandler")
	defer destroyDB()

	data := bytes.NewBuffer([]byte(`[{"ip":"192.0.2.1","ports":[{"port":80,"proto":"tcp","status":"open","reason":"syn-ack","ttl":57}]}]`))

	mux := setupRouter()
	ts := httptest.NewServer(mux)
	defer ts.Close()

	// We need to save some job data before trying to submit any
	saveJob("192.0.2.1", "80", "tcp", "testuser@example.com")

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

// TestTracerouteHandler tests fetching a route, ensuring it fails, uploading
// that route then fetching it.
func TestTracerouteHandler(t *testing.T) {
	createDB("TestTracerouteHandler")
	defer destroyDB()

	route := `
traceroute to 192.0.2.1 (192.0.2.1), 64 hops max, 52 byte packets
1  router.internal (192.168.0.1)  1.308 ms  1.087 ms  0.929 ms
2  server.example.com (192.0.2.1)  8.134 ms !N  6.533 ms !N  6.295 ms !N
`

	mux := setupRouter()
	ts := httptest.NewServer(mux)
	defer ts.Close()

	req, err := http.NewRequest("GET", ts.URL+"/traceroute/192.0.2.1", nil)
	if err != nil {
		t.Fatal(err)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := ioutil.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("expected status %d, got %v: %s", http.StatusNotFound, resp.StatusCode, body)
	}

	postBody := new(bytes.Buffer)
	mp := multipart.NewWriter(postBody)
	mp.WriteField("dest", "192.0.2.1")
	ff, err := mp.CreateFormFile("traceroute", "traceroute")
	ff.Write([]byte(route))
	mp.Close()

	req = httptest.NewRequest("POST", "/traceroute", postBody)
	req.Header.Set("Content-Type", mp.FormDataContentType())
	w := httptest.NewRecorder()
	recvTraceroute(w, req)

	resp = w.Result()
	body, _ = ioutil.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusCreated {
		t.Errorf("expected status %d, got %v: %s", http.StatusCreated, resp.StatusCode, body)
	}

	req, err = http.NewRequest("GET", ts.URL+"/traceroute/192.0.2.1", nil)
	if err != nil {
		t.Fatal(err)
	}

	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	body, _ = ioutil.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected status %d, got %v: %s", http.StatusOK, resp.StatusCode, body)
	}

	if string(body) != route {
		t.Errorf("expect %q, got %q", route, string(body))
	}
}
