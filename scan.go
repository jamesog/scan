package main

import (
	"crypto/tls"
	"database/sql"
	"database/sql/driver"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"html/template"
	"io"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/acme/autocert"

	"github.com/go-chi/chi"
	"github.com/go-chi/chi/middleware"
	"github.com/go-chi/render"
	_ "github.com/mattn/go-sqlite3"
	"github.com/pressly/goose"

	_ "github.com/jamesog/scan/migrations"
)

// Human-readable date-time format
const dateTime = "2006-01-02 15:04"

var (
	// Flag variables
	authDisabled bool
	credsFile    string
	dataDir      string
	httpsAddr    string

	// HTML templates
	tmpl *template.Template

	// Database handle
	db     *sql.DB
	dbFile = "scan.db"
)

func openDB(dsn string) error {
	var err error
	db, err = sql.Open("sqlite3", dsn)
	if err != nil {
		return err
	}

	err = db.Ping()
	if err != nil {
		log.Fatal(err)
	}

	// Run migrations
	goose.SetDialect("sqlite3")
	// Use a temporary directory for goose.Up() - we don't have any .sql files
	// to run, it's all embedded in the binary
	tmpdir, err := ioutil.TempDir(dataDir, "")
	if err != nil {
		log.Fatal(err)
	}
	defer os.RemoveAll(tmpdir)
	log.Println("Checking database migration status")
	goose.Status(db, tmpdir)
	err = goose.Up(db, tmpdir)
	if err != nil {
		log.Fatalf("Error running database migrations: %v\n", err)
	}

	return nil
}

// NullTime "borrowed" from github.com/lib/pq

// NullTime represents a time.Time that may be null. NullTime implements the
// sql.Scanner interface so it can be used as a scan destination, similar to
// sql.NullString.
type NullTime struct {
	Time  time.Time
	Valid bool // Valid is true if Time is not NULL
}

// Scan implements the Scanner interface.
func (nt *NullTime) Scan(value interface{}) error {
	nt.Time, nt.Valid = value.(time.Time)
	return nil
}

// Value implements the Valuer interface.
func (nt NullTime) Value() (driver.Value, error) {
	if !nt.Valid {
		return nil, nil
	}
	return nt.Time, nil
}

// sqlFilter is for constructing data filters ("WHERE" clauses) in a SQL statement
type sqlFilter struct {
	Where  []string
	Values []interface{}
}

// String constructs a SQL WHERE clause.
func (f sqlFilter) String() string {
	if len(f.Where) > 0 {
		return "WHERE " + strings.Join(f.Where, " AND ")
	}
	return ""
}

type port struct {
	Port    int    `json:"port"`
	Proto   string `json:"proto"`
	Status  string `json:"status"`
	Service struct {
		Name   string `json:"name"`
		Banner string `json:"banner"`
	} `json:"service"`
}

// Results posted from masscan
type result struct {
	IP    string `json:"ip"`
	Ports []port `json:"ports"`
}

// Data retrieved from the database for display
type ipInfo struct {
	IP            string
	Port          int
	Proto         string
	FirstSeen     string
	LastSeen      string
	New           bool
	Gone          bool
	HasTraceroute bool
}

// Load all data for displaying in the browser
func loadData(filter sqlFilter) ([]ipInfo, error) {
	qry := fmt.Sprintf(`SELECT ip, port, proto, firstseen, lastseen FROM scan %s ORDER BY port, proto, ip, lastseen`, filter)
	rows, err := db.Query(qry, filter.Values...)
	if err != nil {
		return []ipInfo{}, err
	}

	defer rows.Close()

	var data []ipInfo
	var ip, proto string
	var firstseen, lastseen time.Time
	var port int
	var latest time.Time

	traceroutes, err := loadTraceroutes()
	if err != nil {
		return []ipInfo{}, err
	}

	for rows.Next() {
		err := rows.Scan(&ip, &port, &proto, &firstseen, &lastseen)
		if err != nil {
			return []ipInfo{}, err
		}
		if lastseen.After(latest) {
			latest = lastseen
		}
		var hasTraceroute bool
		if _, ok := traceroutes[ip]; ok {
			hasTraceroute = true
		}
		data = append(data, ipInfo{
			ip,
			port,
			proto,
			firstseen.Format(dateTime),
			lastseen.Format(dateTime),
			false,
			false,
			hasTraceroute})
	}

	for i := range data {
		f, _ := time.Parse(dateTime, data[i].FirstSeen)
		l, _ := time.Parse(dateTime, data[i].LastSeen)
		if f.Equal(l) && l == latest {
			data[i].New = true
		}
		if l.Before(latest) {
			data[i].Gone = true
		}
	}

	return data, nil
}

// Save the results posted
func saveData(results []result) (int64, error) {
	txn, err := db.Begin()
	if err != nil {
		return 0, err
	}

	insert, err := txn.Prepare(`INSERT INTO scan (ip, port, proto, firstseen, lastseen) VALUES (?, ?, ?, ?, ?)`)
	if err != nil {
		txn.Rollback()
		return 0, err
	}
	qry, err := txn.Prepare(`SELECT 1 FROM scan WHERE ip=? AND port=? AND proto=?`)
	if err != nil {
		txn.Rollback()
		return 0, err
	}
	update, err := txn.Prepare(`UPDATE scan SET lastseen=? WHERE ip=? AND port=? AND proto=?`)
	if err != nil {
		txn.Rollback()
		return 0, err
	}

	now := time.Now().UTC().Truncate(time.Minute)
	var count int64

	for _, r := range results {
		// Although it's an array, only one port is in each
		port := r.Ports[0]

		// Skip results which are (usually) banner-only
		// While it would be nice to store banners, we need to restructure a
		// bit to accommodate this and it just inserts duplicate data for now
		if port.Status == "" || port.Service.Name != "" {
			continue
		}

		// Search for the IP/port/proto combo
		// If it exists, update `lastseen`, else insert a new record

		// Because we have to scan into something
		var x int
		err := qry.QueryRow(r.IP, port.Port, port.Proto).Scan(&x)
		switch {
		case err == sql.ErrNoRows:
			_, err = insert.Exec(r.IP, port.Port, port.Proto, now, now)
			if err != nil {
				txn.Rollback()
				return 0, err
			}
			count++
			continue
		case err != nil:
			txn.Rollback()
			return 0, err
		}

		_, err = update.Exec(now, r.IP, port.Port, port.Proto)
		if err != nil {
			txn.Rollback()
			return 0, err
		}

		count++
	}

	txn.Commit()
	return count, nil
}

func loadTraceroutes() (map[string]struct{}, error) {
	ips := make(map[string]struct{})

	rows, err := db.Query(`SELECT dest FROM traceroute`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var ip string
	for rows.Next() {
		err := rows.Scan(&ip)
		if err != nil {
			return nil, err
		}
		if _, ok := ips[ip]; !ok {
			ips[ip] = struct{}{}
		}
	}

	return ips, nil
}

type indexData struct {
	NotAuth       string
	Errors        []string
	Authenticated bool
	User          User
	URI           string
	ActiveOnly    bool
	scanData
}

type scanData struct {
	Total    int
	Latest   int
	New      int
	LastSeen string
	Results  []ipInfo
}

func resultData(ip, fs, ls string) (scanData, error) {
	var filter sqlFilter
	if ip != "" {
		filter.Where = append(filter.Where, `ip LIKE ?`)
		filter.Values = append(filter.Values, fmt.Sprintf("%%%s%%", ip))
	}
	if fs != "" {
		t, _ := time.Parse(dateTime, fs)
		filter.Where = append(filter.Where, `firstseen=?`)
		filter.Values = append(filter.Values, t)
	}
	if ls != "" {
		t, _ := time.Parse(dateTime, ls)
		filter.Where = append(filter.Where, `lastseen=?`)
		filter.Values = append(filter.Values, t)
	}

	results, err := loadData(filter)
	if err != nil {
		return scanData{}, err
	}

	data := scanData{
		Results: results,
		Total:   len(results),
	}

	// Find all the latest results and store the number in the struct
	var latest time.Time
	for _, r := range results {
		last, _ := time.Parse(dateTime, r.LastSeen)
		if last.After(latest) {
			latest = last
		}
	}
	for _, r := range results {
		last, _ := time.Parse(dateTime, r.LastSeen)
		if last.Equal(latest) {
			data.Latest++
		}
		if r.New {
			data.New++
		}
	}
	data.LastSeen = latest.Format(dateTime)

	return data, nil
}

// Handler for GET /
func index(w http.ResponseWriter, r *http.Request) {
	var user User
	if !authDisabled {
		session, err := store.Get(r, "user")
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		if _, ok := session.Values["user"]; !ok {
			data := indexData{URI: r.RequestURI}
			if flash := session.Flashes("unauth_flash"); len(flash) > 0 {
				data.NotAuth = flash[0].(string)
				w.WriteHeader(http.StatusUnauthorized)
				session.Save(r, w)
			}
			tmpl.ExecuteTemplate(w, "index", data)
			return
		}
		v := session.Values["user"]
		switch v.(type) {
		case string:
			user.Email = v.(string)
		case User:
			user = v.(User)
		}
	}

	q := r.URL.Query()
	ip := q.Get("ip")
	firstSeen := q.Get("firstseen")
	lastSeen := q.Get("lastseen")
	_, activeOnly := q["active"]

	results, err := resultData(ip, firstSeen, lastSeen)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	data := indexData{
		Authenticated: true,
		User:          user,
		URI:           r.URL.Path,
		ActiveOnly:    activeOnly,
		scanData:      results,
	}
	tmpl.ExecuteTemplate(w, "index", data)
}

// Handler for GET /ips.json
// This is used as the prefetch for Typeahead.js
func ips(w http.ResponseWriter, r *http.Request) {
	data, err := loadData(sqlFilter{})
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	var ips []string
	for _, r := range data {
		ips = append(ips, r.IP)
	}
	render.JSON(w, r, ips)
	return
}

type jobTime time.Time

func (jt jobTime) String() string {
	t := time.Time(jt)
	if t.IsZero() {
		return ""
	}
	return t.Format(dateTime)
}

func (jt jobTime) IsZero() bool {
	return time.Time(jt).IsZero()
}

type job struct {
	ID          int     `json:"id"`
	CIDR        string  `json:"cidr"`
	Ports       string  `json:"ports"`
	Proto       string  `json:"proto"`
	RequestedBy string  `json:"-"`
	Submitted   jobTime `json:"-"`
	Received    jobTime `json:"-"`
	Count       int64   `json:"-"`
}

func loadJobs(filter sqlFilter) ([]job, error) {
	qry := fmt.Sprintf(`SELECT rowid, cidr, ports, proto, requested_by, submitted, received, count FROM job %s ORDER BY received DESC, submitted, rowid`, filter)
	rows, err := db.Query(qry, filter.Values...)
	if err != nil {
		return []job{}, err
	}

	defer rows.Close()

	var id int
	var cidr, ports, proto, requestedBy string
	var submitted time.Time
	var received NullTime
	var count sql.NullInt64

	var jobs []job

	for rows.Next() {
		err := rows.Scan(&id, &cidr, &ports, &proto, &requestedBy, &submitted, &received, &count)
		if err != nil {
			return []job{}, err
		}

		jobs = append(jobs, job{id, cidr, ports, proto, requestedBy, jobTime(submitted), jobTime(received.Time), count.Int64})
	}

	return jobs, nil
}

func saveJob(cidr, ports, proto, user string) (int64, error) {
	txn, err := db.Begin()
	if err != nil {
		return 0, err
	}

	qry := `INSERT INTO job (cidr, ports, proto, requested_by, submitted) VALUES (?, ?, ?, ?, ?)`
	res, err := txn.Exec(qry, cidr, ports, strings.ToLower(proto), user, time.Now())
	if err != nil {
		txn.Rollback()
		return 0, err
	}

	id, err := res.LastInsertId()
	if err != nil {
		return 0, err
	}

	err = txn.Commit()
	if err != nil {
		return 0, err
	}

	return id, nil
}

func updateJob(id string, count int64) error {
	txn, err := db.Begin()
	if err != nil {
		return err
	}

	qry := `UPDATE job SET received=?, count=? WHERE rowid=?`
	res, err := txn.Exec(qry, time.Now(), count, id)
	rows, _ := res.RowsAffected()
	if err != nil || rows <= 0 {
		txn.Rollback()
		return err
	}

	err = txn.Commit()
	if err != nil {
		return err
	}

	return nil
}

type jobData struct {
	indexData
	JobID []string
	Jobs  []job
}

// Handler for GET and POST /job
func newJob(w http.ResponseWriter, r *http.Request) {
	var user User
	if !authDisabled {
		session, err := store.Get(r, "user")
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		if _, ok := session.Values["user"]; !ok {
			data := jobData{indexData: indexData{URI: r.RequestURI}}
			tmpl.ExecuteTemplate(w, "job", data)
			return
		}
		v := session.Values["user"]
		switch v.(type) {
		case string:
			user.Email = v.(string)
		case User:
			user = v.(User)
		}
	}

	var jobID []string
	var errors []string

	if r.Method == "POST" {
		err := r.ParseForm()
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		f := r.Form
		cidr := f.Get("cidr")
		ports := f.Get("ports")
		proto := f["proto"]

		if cidr == "" {
			errors = append(errors, "CIDR")
		}
		if ports == "" {
			errors = append(errors, "Ports")
		}
		if len(proto) == 0 {
			errors = append(errors, "Protocol")
		}

		// If we have form parameters, save the data as a new job.
		// Multiple protocols can be submitted. These are saved as separate jobs.
		if len(errors) == 0 {
			for i := range proto {
				id, err := saveJob(cidr, ports, proto[i], user.Email)
				if err != nil {
					http.Error(w, err.Error(), http.StatusInternalServerError)
					return
				}
				jobID = append(jobID, strconv.FormatInt(id, 10))
			}
		}
	}

	jobs, err := loadJobs(sqlFilter{})
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Fetch result numbers for display in the navbar
	// Errors aren't fatal here, we can just display 0 results if something
	// goes wrong
	results, _ := resultData("", "", "")

	data := jobData{
		indexData: indexData{
			Errors:        errors,
			Authenticated: true,
			User:          user,
			URI:           r.URL.Path,
			scanData:      results,
		},
		JobID: jobID,
		Jobs:  jobs,
	}

	tmpl.ExecuteTemplate(w, "job", data)
	return
}

// Handler for GET /jobs
func jobs(w http.ResponseWriter, r *http.Request) {
	jobs, err := loadJobs(sqlFilter{
		Where: []string{"received IS NULL"},
	})
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		render.JSON(w, r, err.Error())
	}

	render.JSON(w, r, jobs)
}

func saveResults(w http.ResponseWriter, r *http.Request) (int64, error) {
	if r.Header.Get("Content-Type") != "application/json" {
		w.WriteHeader(http.StatusUnsupportedMediaType)
		return 0, errors.New("invalid Content-Type")
	}

	res := new([]result)

	err := json.NewDecoder(r.Body).Decode(&res)
	if err != nil {
		return 0, err
	}

	count, err := saveData(*res)
	if err != nil {
		return 0, err
	}

	return count, nil
}

// Handler for POST /results
func recvResults(w http.ResponseWriter, r *http.Request) {
	_, err := saveResults(w, r)
	if err != nil {
		return
	}
}

// Handler for PUT /results/{id}
func recvJobResults(w http.ResponseWriter, r *http.Request) {
	job := chi.URLParam(r, "id")

	// Check if the job ID is valid
	_, err := loadJobs(sqlFilter{
		Where:  []string{"rowid=?"},
		Values: []interface{}{job},
	})
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// Insert the results as normal
	count, err := saveResults(w, r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Update the job
	err = updateJob(job, count)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
}

// Handler for POST /traceroute
func recvTraceroute(w http.ResponseWriter, r *http.Request) {
	dest := r.FormValue("dest")
	f, _, err := r.FormFile("traceroute")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	trace, err := ioutil.ReadAll(f)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	txn, err := db.Begin()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	_, err = txn.Exec(`INSERT OR REPLACE INTO traceroute (dest, path) VALUES (?, ?)`, dest, trace)
	if err != nil {
		txn.Rollback()
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	err = txn.Commit()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Location", path.Join(r.URL.Path, dest))
	w.WriteHeader(http.StatusCreated)
}

// Handler for GET /traceroute/{ip}
func traceroute(w http.ResponseWriter, r *http.Request) {
	ip := chi.URLParam(r, "ip")

	var path string
	err := db.QueryRow(`SELECT path FROM traceroute WHERE dest = ?`, ip).Scan(&path)
	switch {
	case err == sql.ErrNoRows:
		http.Error(w, "Traceroute not found", http.StatusNotFound)
		return
	case err != nil:
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	io.WriteString(w, path)
}

// redirectHTTPS is a middleware for redirecting non-HTTPS requests to HTTPS
func redirectHTTPS(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, httpsPort, err := net.SplitHostPort(httpsAddr)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		if r.TLS == nil {
			url := r.URL
			url.Scheme = "https"
			host, _, err := net.SplitHostPort(r.Host)
			if err != nil {
				url.Host = r.Host
			} else {
				url.Host = host
			}
			if httpsPort != "443" {
				url.Host = net.JoinHostPort(url.Host, httpsPort)
			}
			http.Redirect(w, r, url.String(), http.StatusMovedPermanently)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func setupRouter(middlewares ...func(http.Handler) http.Handler) *chi.Mux {
	r := chi.NewRouter()
	r.Use(middleware.RealIP)
	r.Use(middleware.Logger)
	for _, mw := range middlewares {
		r.Use(mw)
	}

	staticDir := filepath.Join(dataDir, "static")
	static := http.StripPrefix("/static", http.FileServer(http.Dir(staticDir)))

	r.Get("/", index)
	r.Get("/auth", authHandler)
	r.Get("/ips.json", ips)
	r.Route("/job", func(r chi.Router) {
		r.Get("/", newJob)
		r.Post("/", newJob)
	})
	r.Get("/jobs", jobs)
	r.Get("/login", loginHandler)
	r.Get("/logout", logoutHandler)
	r.Handle("/metrics", metrics())
	r.Post("/results", recvResults)
	r.Put("/results/{id}", recvJobResults)
	r.Get("/static/*", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		static.ServeHTTP(w, r)
	}))
	r.Post("/traceroute", recvTraceroute)
	r.Get("/traceroute/{ip}", traceroute)

	return r
}

func setupTemplates() {
	funcMap := template.FuncMap{
		"join": func(sep string, s []string) string {
			return strings.Join(s, sep)
		},
	}

	tmpl = template.Must(template.New("").Funcs(funcMap).
		ParseGlob(filepath.Join(dataDir, "views/*.html")))
}

func main() {
	flag.BoolVar(&authDisabled, "no-auth", false, "Disable authentication")
	flag.StringVar(&credsFile, "credentials", "client_secret.json",
		"OAuth 2.0 credentials `file`\n"+
			"Relative paths are taken as relative to -data.dir")
	flag.StringVar(&dataDir, "data.dir", ".", "Data directory `path`")
	httpAddr := flag.String("http.addr", ":80", "HTTP `address`:port")
	flag.StringVar(&httpsAddr, "https.addr", ":443", "HTTPS `address`:port")
	enableTLS := flag.Bool("tls", false, "Enable AutoTLS")
	tlsHostname := flag.String("tls.hostname", "", "(Optional) Restrict AutoTLS to `hostname`")
	flag.Parse()

	if !filepath.IsAbs(credsFile) {
		credsFile = filepath.Join(dataDir, credsFile)
	}

	oauthConfig()

	if err := openDB(filepath.Join(dataDir, dbFile)); err != nil {
		log.Fatalf("failed to open database: %v", err)
	}

	setupTemplates()

	var middlewares []func(http.Handler) http.Handler

	if authDisabled {
		fmt.Fprintf(os.Stderr, "%sAuthentication Disabled%s\n", "\033[31m", "\033[0m")
	}

	var m *autocert.Manager
	if *enableTLS {
		m = &autocert.Manager{
			Cache:  autocert.DirCache(filepath.Join(dataDir, ".cache")),
			Prompt: autocert.AcceptTOS,
		}
		if *tlsHostname != "" {
			m.HostPolicy = autocert.HostWhitelist(*tlsHostname)
		}
		middlewares = append(middlewares, redirectHTTPS)
	}

	r := setupRouter(middlewares...)

	httpSrv := &http.Server{
		Addr:         *httpAddr,
		Handler:      r,
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 5 * time.Second,
		IdleTimeout:  120 * time.Second,
	}

	if *enableTLS {
		httpsSrv := &http.Server{
			Addr:         httpsAddr,
			Handler:      r,
			ReadTimeout:  5 * time.Second,
			WriteTimeout: 5 * time.Second,
			IdleTimeout:  120 * time.Second,

			TLSConfig: &tls.Config{
				GetCertificate:           m.GetCertificate,
				PreferServerCipherSuites: true,
				CurvePreferences: []tls.CurveID{
					tls.CurveP256,
					tls.X25519,
				},
				MinVersion: tls.VersionTLS12,
				CipherSuites: []uint16{
					tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
					tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
					tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
					tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
					tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
					tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
				},
			},
		}
		go func() { log.Fatal(httpSrv.ListenAndServe()) }()
		log.Fatal(httpsSrv.ListenAndServeTLS("", ""))
	}

	log.Fatal(httpSrv.ListenAndServe())
}
