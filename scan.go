//go:generate go-bindata views static/...
package main

import (
	"bytes"
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
	"mime"
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
	verbose      bool

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

	if verbose {
		log.Println("Checking database migration status")
		goose.Status(db, tmpdir)
	} else {
		// Discard Goose's log output
		goose.SetLogger(log.New(ioutil.Discard, "", 0))
	}
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

func toNullInt64(i *int64) sql.NullInt64 {
	var ni sql.NullInt64
	if i != nil {
		ni = sql.NullInt64{Int64: *i, Valid: true}
	}
	return ni
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
	FirstSeen     scanTime
	LastSeen      scanTime
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

	submission, err := loadSubmission(sqlFilter{Where: []string{"job_id IS NULL"}})
	if err == nil {
		latest = time.Time(submission.Time)
	}

	for rows.Next() {
		err := rows.Scan(&ip, &port, &proto, &firstseen, &lastseen)
		if err != nil {
			log.Println("loadData: error scanning table:", err)
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
			IP:            ip,
			Port:          port,
			Proto:         proto,
			FirstSeen:     scanTime(firstseen),
			LastSeen:      scanTime(lastseen),
			New:           firstseen.Equal(lastseen) && lastseen == latest,
			Gone:          lastseen.Before(latest),
			HasTraceroute: hasTraceroute})
	}

	return data, nil
}

// Save the results posted
func saveData(results []result, now time.Time) (int64, error) {
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

func loadSubmission(filter sqlFilter) (submission, error) {
	var host string
	var job sql.NullInt64
	var subTime NullTime

	qry := fmt.Sprintf(`SELECT host, job_id, submission_time FROM submission %s ORDER BY rowid DESC LIMIT 1`, filter)
	err := db.QueryRow(qry, filter.Values...).Scan(&host, &job, &subTime)
	if err != nil && err != sql.ErrNoRows {
		log.Println("loadSubmission: error scanning table:", err)
		return submission{}, err
	}

	return submission{Host: host, Job: job.Int64, Time: scanTime(subTime.Time.UTC())}, nil
}

func saveSubmission(host string, job *int64, now time.Time) error {
	txn, err := db.Begin()
	if err != nil {
		return err
	}

	qry := `INSERT INTO submission (host, job_id, submission_time) VALUES (?, ?, ?)`
	_, err = txn.Exec(qry, host, toNullInt64(job), now)
	if err != nil {
		txn.Rollback()
		return err
	}

	err = txn.Commit()
	if err != nil {
		return err
	}

	if job != nil {
		gaugeJobSubmission.Set(float64(now.Unix()))
	} else {
		gaugeSubmission.Set(float64(now.Unix()))
	}

	return nil
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
	AllResults    bool
	Submission    submission
	scanData
}

type scanData struct {
	Total    int
	Latest   int
	New      int
	LastSeen int64
	Results  []ipInfo
}

type submission struct {
	Host string
	Job  int64
	Time scanTime
}

func resultData(ip, fs, ls string) (scanData, error) {
	var filter sqlFilter
	if ip != "" {
		filter.Where = append(filter.Where, `ip LIKE ?`)
		filter.Values = append(filter.Values, fmt.Sprintf("%%%s%%", ip))
	}
	if fs != "" {
		i, err := strconv.ParseInt(fs, 10, 0)
		if err != nil {
			log.Printf("couldn't parse firstseen value %q: %v", ls, err)
		} else {
			t := time.Unix(i, 0).UTC()
			filter.Where = append(filter.Where, `firstseen=?`)
			filter.Values = append(filter.Values, t)
		}
	}
	if ls != "" {
		i, err := strconv.ParseInt(ls, 10, 0)
		if err != nil {
			log.Printf("couldn't parse lastseen value %q: %v", ls, err)
		} else {
			t := time.Unix(i, 0).UTC()
			filter.Where = append(filter.Where, `lastseen=?`)
			filter.Values = append(filter.Values, t)
		}
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
	// Set latest to Unix(0, 0) rather than the default zero value of the type
	// to allow tests to receive an actual 0 value rather than a negative int
	latest := time.Unix(0, 0)
	for _, r := range results {
		last := time.Time(r.LastSeen)
		if last.After(latest) {
			latest = last
		}
	}
	for _, r := range results {
		if !r.Gone {
			data.Latest++
		}
		if r.New {
			data.New++
		}
	}
	data.LastSeen = latest.Unix()

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
	_, allResults := q["all"]

	results, err := resultData(ip, firstSeen, lastSeen)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	sub, err := loadSubmission(sqlFilter{})
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	data := indexData{
		Authenticated: true,
		User:          user,
		URI:           r.URL.Path,
		AllResults:    allResults,
		Submission:    sub,
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

type scanTime time.Time

func (st scanTime) String() string {
	t := time.Time(st)
	if t.IsZero() {
		return ""
	}
	return t.Format(dateTime)
}

func (st scanTime) IsZero() bool {
	return time.Time(st).IsZero()
}

func (st scanTime) Unix() int64 {
	return time.Time(st).Unix()
}

func saveResults(w http.ResponseWriter, r *http.Request, now time.Time) (int64, error) {
	if r.Header.Get("Content-Type") != "application/json" {
		w.WriteHeader(http.StatusUnsupportedMediaType)
		return 0, errors.New("invalid Content-Type")
	}

	res := new([]result)

	err := json.NewDecoder(r.Body).Decode(&res)
	if err != nil {
		return 0, err
	}

	count, err := saveData(*res, now)
	if err != nil {
		return 0, err
	}

	return count, nil
}

// Handler for POST /results
func recvResults(w http.ResponseWriter, r *http.Request) {
	now := time.Now().UTC().Truncate(time.Second)
	_, err := saveResults(w, r, now)
	if err != nil {
		log.Println("recvResults: error saving results:", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	ip, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		ip = r.RemoteAddr
	}
	err = saveSubmission(ip, nil, now)
	if err != nil {
		log.Println("recvResults: error saving submission:", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Update metrics with latest data
	results, err := resultData("", "", "")
	if err != nil {
		log.Printf("saveResults: error fetching results for metrics update: %v\n", err)
	} else {
		gaugeTotal.Set(float64(results.Total))
		gaugeLatest.Set(float64(results.Latest))
		gaugeNew.Set(float64(results.New))
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

type assetMap map[string]asset

var assets assetMap

// loadAssetsFromDir gets all assets whose parent directory is "name" and
// returns a map of the asset path to the asset function.
func loadAssetsFromDir(name string) assetMap {
	assets = make(assetMap)
	for b := range _bindata {
		if strings.HasPrefix(b, name+"/") {
			a, err := _bindata[b]()
			if err != nil {
				log.Printf("Failed to load asset %s: %v", b, err)
			}
			assets[b] = *a
		}
	}
	return assets
}

// staticHandler returns a static asset from the map generated by
// loadAssetsFromDir.
func staticHandler(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/")
	if a, ok := assets[path]; ok {
		ct := mime.TypeByExtension(filepath.Ext(a.info.Name()))
		if ct == "" {
			ct = http.DetectContentType(a.bytes)
		}
		w.Header().Set("Content-Type", ct)
		b := bytes.NewReader(a.bytes)
		http.ServeContent(w, r, a.info.Name(), a.info.ModTime(), b)
	}

	http.NotFound(w, r)
}

func setupRouter(middlewares ...func(http.Handler) http.Handler) *chi.Mux {
	r := chi.NewRouter()
	r.Use(middleware.RealIP)
	r.Use(middleware.Logger)
	for _, mw := range middlewares {
		r.Use(mw)
	}

	assets = loadAssetsFromDir("static")

	r.Get("/", index)
	r.Route("/admin", func(r chi.Router) {
		r.Get("/", adminHandler)
		r.Post("/", adminHandler)
	})
	r.Get("/auth", authHandler)
	r.Get("/ips.json", ips)
	r.Route("/job", func(r chi.Router) {
		r.Get("/", newJob)
		r.Post("/", newJob)
	})
	r.Get("/jobs", jobs)
	r.Get("/login", loginHandler)
	r.Get("/logout", logoutHandler)
	r.Post("/results", recvResults)
	r.Put("/results/{id}", recvJobResults)
	r.Get("/static/*", staticHandler)
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

	tmpl = template.New("").Funcs(funcMap)

	views, err := AssetDir("views")
	if err != nil {
		log.Fatal(err)
	}

	for _, file := range views {
		b, err := Asset("views/" + file)
		if err != nil {
			log.Println(err)
			continue
		}
		var t *template.Template
		t = tmpl.New(filepath.Base(file))
		template.Must(t.Parse(string(b)))
	}
}

func main() {
	flag.BoolVar(&authDisabled, "no-auth", false, "Disable authentication")
	flag.StringVar(&credsFile, "credentials", "client_secret.json",
		"OAuth 2.0 credentials `file`\n"+
			"Relative paths are taken as relative to -data.dir")
	flag.StringVar(&dataDir, "data.dir", ".", "Data directory `path`")
	httpAddr := flag.String("http.addr", ":80", "HTTP `address`:port")
	flag.StringVar(&httpsAddr, "https.addr", ":443", "HTTPS `address`:port")
	metricsAddr := flag.String("metrics.addr", "localhost:3000", "Metrics `address`:port")
	metricsTLS := flag.Bool("metrics.tls", false, "Enable AutoTLS for metrics, if -tls enabled\n"+
		"This is useful when exposing metrics on a public interface")
	enableTLS := flag.Bool("tls", false, "Enable AutoTLS")
	tlsHostname := flag.String("tls.hostname", "", "(Optional) Restrict AutoTLS to `hostname`")
	flag.BoolVar(&verbose, "v", false, "Enable verbose logging")
	flag.Parse()

	// Disable TLS on metrics if TLS wasn't generally enabled as autocert
	// isn't set up.
	if !*enableTLS && *metricsTLS {
		log.Println("Info: Disabling -metrics.tls as -tls was not enabled")
		*metricsTLS = false
	}

	if !filepath.IsAbs(credsFile) {
		credsFile = filepath.Join(dataDir, credsFile)
	}

	if !authDisabled {
		oauthConfig()
	}

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
		middlewares = append(middlewares, m.HTTPHandler, redirectHTTPS)
	}

	r := setupRouter(middlewares...)

	// Common http.Server timeout values
	readTimeout := 5 * time.Second
	writeTimeout := 5 * time.Second
	idleTimeout := 120 * time.Second

	httpSrv := &http.Server{
		Addr:         *httpAddr,
		Handler:      r,
		ReadTimeout:  readTimeout,
		WriteTimeout: writeTimeout,
		IdleTimeout:  idleTimeout,
	}

	metricsMux := chi.NewRouter()
	metricsMux.Use(middleware.RealIP)
	metricsMux.Use(middleware.Logger)
	if *metricsTLS {
		metricsMux.Use(redirectHTTPS)
	}
	metricsMux.Handle("/metrics", metrics())
	metricsSrv := &http.Server{
		Addr:         *metricsAddr,
		Handler:      metricsMux,
		ReadTimeout:  readTimeout,
		WriteTimeout: writeTimeout,
		IdleTimeout:  idleTimeout,
	}

	if !*metricsTLS {
		log.Println("Metrics HTTP server starting on", metricsSrv.Addr)
		go func() { log.Fatal(metricsSrv.ListenAndServe()) }()
	}

	if *enableTLS {
		tlsConfig := &tls.Config{
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
		}

		httpsSrv := &http.Server{
			Addr:         httpsAddr,
			Handler:      r,
			ReadTimeout:  readTimeout,
			WriteTimeout: writeTimeout,
			IdleTimeout:  idleTimeout,
			TLSConfig:    tlsConfig,
		}
		if *metricsTLS {
			metricsSrv.Addr = *metricsAddr
			metricsSrv.Handler = metricsMux
			metricsSrv.TLSConfig = tlsConfig
			log.Println("Metrics HTTPS server starting on", metricsSrv.Addr)
			go func() { log.Fatal(metricsSrv.ListenAndServeTLS("", "")) }()
		}
		log.Println("HTTPS server starting on", httpsSrv.Addr)
		go func() { log.Fatal(httpsSrv.ListenAndServeTLS("", "")) }()
	}

	log.Println("HTTP server starting on", httpSrv.Addr)
	log.Fatal(httpSrv.ListenAndServe())
}
