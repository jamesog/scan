//go:generate go-bindata views static/...
package main

import (
	"bytes"
	"crypto/tls"
	"database/sql"
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
	"strings"
	"time"

	"golang.org/x/crypto/acme/autocert"

	"github.com/go-chi/chi"
	"github.com/go-chi/chi/middleware"

	"github.com/jamesog/scan/internal/sqlite"
	"github.com/jamesog/scan/pkg/scan"
)

var (
	// Flag variables
	authDisabled bool
	credsFile    string
	dataDir      string
	httpsAddr    string
	verbose      bool

	// HTML templates
	tmpl *template.Template
)

type storage interface {
	LoadData(filter sqlite.SQLFilter) ([]scan.IPInfo, error)
	ResultData(ip, fs, ls string) (scan.Data, error)
	SaveData(results []scan.Result, now time.Time) (int64, error)
	LoadSubmission(filter sqlite.SQLFilter) (scan.Submission, error)
	SaveSubmission(host string, job *int64, now time.Time) error
	LoadTracerouteIPs() (map[string]struct{}, error)
	LoadTraceroute(dest string) (string, error)
	SaveTraceroute(dest, trace string) error
	LoadJobs(filter sqlite.SQLFilter) ([]scan.Job, error)
	LoadJobSubmission() (scan.Submission, error)
	SaveJob(cidr, ports, proto, user string) (int64, error)
	UpdateJob(id string, count int64) error
	LoadUsers() ([]string, error)
	LoadGroups() ([]string, error)
	UserExists(email string) (bool, error)
	SaveUser(email string) error
	DeleteUser(email string) error
	SaveAudit(ts time.Time, user, event, info string) error
}

type indexData struct {
	NotAuth       string
	Errors        []string
	Authenticated bool
	User          User
	URI           string
	AllResults    bool
	Submission    scan.Submission
	scan.Data
}

type App struct {
	db storage
}

// Handler for GET /
func (app *App) index(w http.ResponseWriter, r *http.Request) {
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
		switch v := v.(type) {
		case string:
			user.Email = v
		case User:
			user = v
		}
	}

	q := r.URL.Query()
	ip := q.Get("ip")
	firstSeen := q.Get("firstseen")
	lastSeen := q.Get("lastseen")
	_, allResults := q["all"]

	results, err := app.db.ResultData(ip, firstSeen, lastSeen)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	sub, err := app.db.LoadSubmission(sqlite.SQLFilter{})
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
		Data:          results,
	}
	tmpl.ExecuteTemplate(w, "index", data)
}

func (app *App) saveResults(w http.ResponseWriter, r *http.Request, now time.Time) (int64, error) {
	if r.Header.Get("Content-Type") != "application/json" {
		w.WriteHeader(http.StatusUnsupportedMediaType)
		return 0, errors.New("invalid Content-Type")
	}

	res := new([]scan.Result)

	err := json.NewDecoder(r.Body).Decode(&res)
	if err != nil {
		return 0, err
	}

	count, err := app.db.SaveData(*res, now)
	if err != nil {
		return 0, err
	}

	return count, nil
}

// Handler for POST /results
func (app *App) recvResults(w http.ResponseWriter, r *http.Request) {
	now := time.Now().UTC().Truncate(time.Second)
	_, err := app.saveResults(w, r, now)
	if err != nil {
		log.Println("recvResults: error saving results:", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	ip, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		ip = r.RemoteAddr
	}
	err = app.db.SaveSubmission(ip, nil, now)
	if err != nil {
		log.Println("recvResults: error saving submission:", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Update metrics with latest data
	results, err := app.db.ResultData("", "", "")
	if err != nil {
		log.Printf("saveResults: error fetching results for metrics update: %v\n", err)
	} else {
		gaugeSubmission.Set(float64(now.Unix()))
		gaugeTotal.Set(float64(results.Total))
		gaugeLatest.Set(float64(results.Latest))
		gaugeNew.Set(float64(results.New))
	}
}

// Handler for POST /traceroute
func (app *App) recvTraceroute(w http.ResponseWriter, r *http.Request) {
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

	err = app.db.SaveTraceroute(dest, string(trace))
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Location", path.Join(r.URL.Path, dest))
	w.WriteHeader(http.StatusCreated)
}

// Handler for GET /traceroute/{ip}
func (app *App) traceroute(w http.ResponseWriter, r *http.Request) {
	ip := chi.URLParam(r, "ip")

	path, err := app.db.LoadTraceroute(ip)
	switch {
	case errors.Is(err, sql.ErrNoRows):
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

func (app *App) setupRouter(middlewares ...func(http.Handler) http.Handler) *chi.Mux {
	r := chi.NewRouter()
	r.Use(middleware.RealIP)
	r.Use(middleware.Logger)
	for _, mw := range middlewares {
		r.Use(mw)
	}

	assets = loadAssetsFromDir("static")

	r.Get("/", app.index)
	r.Route("/admin", func(r chi.Router) {
		r.Get("/", app.adminHandler)
		r.Post("/", app.adminHandler)
	})
	r.Get("/auth", app.authHandler)
	r.Route("/job", func(r chi.Router) {
		r.Get("/", app.newJob)
		r.Post("/", app.newJob)
	})
	r.Get("/jobs", app.jobs)
	r.Get("/login", app.loginHandler)
	r.Get("/logout", app.logoutHandler)
	r.Post("/results", app.recvResults)
	r.Put("/results/{id}", app.recvJobResults)
	r.Get("/static/*", staticHandler)
	r.Post("/traceroute", app.recvTraceroute)
	r.Get("/traceroute/{ip}", app.traceroute)

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
		t := tmpl.New(filepath.Base(file))
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

	db, err := sqlite.Open(filepath.Join(dataDir, sqlite.DefaultDBFile))
	if err != nil {
		log.Fatalf("failed to open database: %v", err)
	}
	app := &App{db: db}

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

	r := app.setupRouter(middlewares...)

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
	metricsMux.Handle("/metrics", app.metrics())
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
