package main

import (
	"database/sql"
	"flag"
	"fmt"
	"html/template"
	"io"
	"net/http"
	"strings"
	"time"

	"golang.org/x/crypto/acme/autocert"

	"github.com/labstack/echo"
	"github.com/labstack/echo/middleware"
	"github.com/labstack/gommon/color"
	_ "github.com/mattn/go-sqlite3"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// Human-readable date-time format
const dateTime = "2006-01-02 15:04"

var authDisabled bool
var dbFile = "scan.db"

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
	IP        string
	Port      int
	Proto     string
	FirstSeen string
	LastSeen  string
	New       bool
}

// Load all data for displaying in the browser
func load(s, fs, ls string) ([]ipInfo, error) {
	db, err := sql.Open("sqlite3", dbFile)
	if err != nil {
		return []ipInfo{}, err
	}
	defer db.Close()

	var where string
	var cond []string
	var params []interface{}
	if s != "" {
		cond = append(cond, `ip LIKE ?`)
		params = append(params, fmt.Sprintf("%%%s%%", s))
	}
	if fs != "" {
		cond = append(cond, `firstseen= ?`)
		params = append(params, fs)
	}
	if ls != "" {
		cond = append(cond, `lastseen= ?`)
		params = append(params, ls)
	}
	if len(cond) > 0 {
		where = fmt.Sprintf("WHERE %s", strings.Join(cond, " AND "))
	}

	qry := fmt.Sprintf(`SELECT ip, port, proto, firstseen, lastseen FROM scan %s ORDER BY port, proto, ip, lastseen`, where)
	rows, err := db.Query(qry, params...)
	if err != nil {
		return []ipInfo{}, err
	}

	defer rows.Close()

	var data []ipInfo
	var ip, proto, firstseen, lastseen string
	var port int
	var latest time.Time

	for rows.Next() {
		err := rows.Scan(&ip, &port, &proto, &firstseen, &lastseen)
		if err != nil {
			return []ipInfo{}, err
		}
		last, _ := time.Parse(dateTime, lastseen)
		if last.After(latest) {
			latest = last
		}
		data = append(data, ipInfo{ip, port, proto, firstseen, lastseen, false})
	}

	for i := range data {
		f, _ := time.Parse(dateTime, data[i].FirstSeen)
		l, _ := time.Parse(dateTime, data[i].LastSeen)
		if f.Equal(l) && l == latest {
			data[i].New = true
		}
	}

	return data, nil
}

// Save the results posted
func save(results []result) error {
	db, err := sql.Open("sqlite3", dbFile)
	if err != nil {
		return err
	}
	defer db.Close()

	txn, err := db.Begin()
	if err != nil {
		return err
	}

	insert, err := txn.Prepare(`INSERT INTO scan (ip, port, proto, firstseen, lastseen) VALUES (?, ?, ?, ?, ?)`)
	if err != nil {
		txn.Rollback()
		return err
	}
	qry, err := db.Prepare(`SELECT 1 FROM scan WHERE ip=? AND port=? AND proto=?`)
	if err != nil {
		txn.Rollback()
		return err
	}
	update, err := txn.Prepare(`UPDATE scan SET lastseen=? WHERE ip=? AND port=? AND proto=?`)
	if err != nil {
		txn.Rollback()
		return err
	}

	now := time.Now().Format(dateTime)

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
				return err
			}
			continue
		case err != nil:
			txn.Rollback()
			return err
		}

		_, err = update.Exec(now, r.IP, port.Port, port.Proto)
		if err != nil {
			txn.Rollback()
			return err
		}
	}

	txn.Commit()
	return nil
}

// Template is a template
type Template struct {
	templates *template.Template
}

// Render renders template
func (t *Template) Render(w io.Writer, name string, data interface{}, c echo.Context) error {
	return t.templates.ExecuteTemplate(w, name, data)
}

type indexData struct {
	Authenticated bool
	User          string
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
	results, err := load(ip, fs, ls)
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
func index(c echo.Context) error {
	var user string
	if !authDisabled {
		session, err := store.Get(c.Request(), "user")
		if err != nil {
			return c.String(http.StatusInternalServerError, err.Error())
		}
		if _, ok := session.Values["user"]; !ok {
			data := indexData{}
			return c.Render(http.StatusOK, "index", data)
		}
		user = session.Values["user"].(string)
	}

	ip := c.QueryParam("ip")
	firstSeen := c.QueryParam("firstseen")
	lastSeen := c.QueryParam("lastseen")

	results, err := resultData(ip, firstSeen, lastSeen)
	if err != nil {
		return c.String(http.StatusInternalServerError, err.Error())
	}

	data := indexData{Authenticated: true, User: user, scanData: results}

	return c.Render(http.StatusOK, "index", data)
}

// Handler for GET /ips.json
// This is used as the prefetch for Typeahead.js
func ips(c echo.Context) error {
	data, err := load("", "", "")
	if err != nil {
		c.String(http.StatusInternalServerError, err.Error())
	}
	var ips []string
	for _, r := range data {
		ips = append(ips, r.IP)
	}
	return c.JSON(http.StatusOK, ips)
}

// Handler for POST /results
func recvResults(c echo.Context) error {
	res := new([]result)
	err := c.Bind(res)
	if err != nil {
		return c.String(http.StatusInternalServerError, err.Error())
	}

	err = save(*res)
	if err != nil {
		return c.String(http.StatusInternalServerError, err.Error())
	}

	return c.NoContent(http.StatusOK)
}

func main() {
	flag.BoolVar(&authDisabled, "no-auth", false, "Disable authentication")
	httpAddr := flag.String("http.addr", ":80", "HTTP address:port")
	httpsAddr := flag.String("https.addr", ":443", "HTTPS address:port")
	tls := flag.Bool("tls", false, "Enable AutoTLS")
	tlsHostname := flag.String("tls.hostname", "", "(Optional) Hostname to restrict AutoTLS")
	flag.Parse()

	t := &Template{
		templates: template.Must(template.ParseGlob("views/*.html")),
	}

	e := echo.New()

	if authDisabled {
		color.Println(color.Red("Authentication Disabled"))
	}

	if *tls {
		if *tlsHostname != "" {
			e.AutoTLSManager.HostPolicy = autocert.HostWhitelist(*tlsHostname)
		}
		e.AutoTLSManager.Cache = autocert.DirCache(".cache")
		e.Pre(middleware.HTTPSRedirect())
	}

	e.HideBanner = true
	e.Renderer = t
	e.Use(middleware.Logger())
	e.GET("/", index)
	e.GET("/auth", authHandler)
	e.GET("/login", loginHandler)
	e.GET("/ips.json", ips)
	e.POST("/results", recvResults)
	e.Static("/static", "static")
	e.GET("/metrics", echo.WrapHandler(promhttp.Handler()))

	// TODO(jamesog): Remove this and instrument directly from the receive handler
	go metrics()

	if *tls {
		go func() { e.Logger.Fatal(e.Start(*httpAddr)) }()
		e.Logger.Fatal(e.StartAutoTLS(*httpsAddr))
	}
	e.Logger.Fatal(e.Start(*httpAddr))
}
