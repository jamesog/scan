package sqlite

import (
	"database/sql"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/jamesog/scan/pkg/scan"
	_ "github.com/mattn/go-sqlite3"
	"github.com/pressly/goose"
)

// DefaultDBFile is the default SQLite database file name.
const DefaultDBFile = "scan.db"

// DB is the database.
type DB struct {
	*sql.DB
}

func toNullInt64(i *int64) sql.NullInt64 {
	var ni sql.NullInt64
	if i != nil {
		ni = sql.NullInt64{Int64: *i, Valid: true}
	}
	return ni
}

// Open creates a new SQLite database object.
func Open(dsn string) (*DB, error) {
	var err error
	db, err := sql.Open("sqlite3", dsn)
	if err != nil {
		return nil, err
	}

	err = db.Ping()
	if err != nil {
		log.Fatal(err)
	}

	// Run migrations
	goose.SetDialect("sqlite3")
	// Use a temporary directory for goose.Up() - we don't have any .sql files
	// to run, it's all embedded in the binary
	tmpdir, err := ioutil.TempDir(filepath.Dir(dsn), "")
	if err != nil {
		log.Fatal(err)
	}
	defer os.RemoveAll(tmpdir)

	// FIXME(jamesog): The verbose flag isn't accessible here anymore
	// if verbose {
	// 	log.Println("Checking database migration status")
	// 	goose.Status(db, tmpdir)
	// } else {
	// Discard Goose's log output
	goose.SetLogger(log.New(ioutil.Discard, "", 0))
	// }
	err = goose.Up(db, tmpdir)
	if err != nil {
		log.Fatalf("Error running database migrations: %v\n", err)
	}

	return &DB{DB: db}, nil
}

// SQLFilter is for constructing data filters ("WHERE" clauses) in a SQL statement
type SQLFilter struct {
	Where  []string
	Values []interface{}
}

// String constructs a SQL WHERE clause.
func (f SQLFilter) String() string {
	if len(f.Where) > 0 {
		return "WHERE " + strings.Join(f.Where, " AND ")
	}
	return ""
}

// LoadData loads all data for displaying in the browser.
func (db *DB) LoadData(filter SQLFilter) ([]scan.IPInfo, error) {
	qry := fmt.Sprintf(`SELECT ip, port, proto, firstseen, lastseen FROM scan %s ORDER BY port, proto, ip, lastseen`, filter)
	rows, err := db.Query(qry, filter.Values...)
	if err != nil {
		return []scan.IPInfo{}, err
	}

	defer rows.Close()

	var data []scan.IPInfo
	var ip, proto string
	var firstseen, lastseen time.Time
	var port int
	var latest time.Time

	tracerouteIPs, err := db.LoadTracerouteIPs()
	if err != nil {
		return []scan.IPInfo{}, err
	}

	submission, err := db.LoadSubmission(SQLFilter{Where: []string{"job_id IS NULL"}})
	if err == nil {
		latest = submission.Time.Time
	}

	for rows.Next() {
		err := rows.Scan(&ip, &port, &proto, &firstseen, &lastseen)
		if err != nil {
			log.Println("loadData: error scanning table:", err)
			return []scan.IPInfo{}, err
		}
		if lastseen.After(latest) {
			latest = lastseen
		}
		var hasTraceroute bool
		if _, ok := tracerouteIPs[ip]; ok {
			hasTraceroute = true
		}
		data = append(data, scan.IPInfo{
			IP:            ip,
			Port:          port,
			Proto:         proto,
			FirstSeen:     scan.Time{Time: firstseen},
			LastSeen:      scan.Time{Time: lastseen},
			New:           firstseen.Equal(lastseen) && lastseen == latest,
			Gone:          lastseen.Before(latest),
			HasTraceroute: hasTraceroute})
	}

	return data, nil
}

// ResultData retrieves stored results. Each argument is optional and allows
// searching by IP address, first seen and last seen.
func (db *DB) ResultData(ip, fs, ls string) (scan.Data, error) {
	var filter SQLFilter
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

	results, err := db.LoadData(filter)
	if err != nil {
		return scan.Data{}, err
	}

	data := scan.Data{
		Results: results,
		Total:   len(results),
	}

	// Find all the latest results and store the number in the struct
	// Set latest to Unix(0, 0) rather than the default zero value of the type
	// to allow tests to receive an actual 0 value rather than a negative int
	latest := time.Unix(0, 0)
	for _, r := range results {
		last := r.LastSeen.Time
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

// SaveData saves the results posted.
func (db *DB) SaveData(results []scan.Result, now time.Time) (int64, error) {
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

// LoadSubmission retrieves the stored submissions.
func (db *DB) LoadSubmission(filter SQLFilter) (scan.Submission, error) {
	var host string
	var job sql.NullInt64
	var subTime sql.NullTime

	qry := fmt.Sprintf(`SELECT host, job_id, submission_time FROM submission %s ORDER BY rowid DESC LIMIT 1`, filter)
	err := db.QueryRow(qry, filter.Values...).Scan(&host, &job, &subTime)
	if err != nil && err != sql.ErrNoRows {
		log.Println("loadSubmission: error scanning table:", err)
		return scan.Submission{}, err
	}

	return scan.Submission{Host: host, Job: job.Int64, Time: scan.Time{Time: subTime.Time.UTC()}}, nil
}

// SaveSubmission stores when and which host just submitted data.
func (db *DB) SaveSubmission(host string, job *int64, now time.Time) error {
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

	return nil
}

// LoadTracerouteIPs retrieves the stored traceroutes.
func (db *DB) LoadTracerouteIPs() (map[string]struct{}, error) {
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

// LoadTraceroute retrieves a traceroute.
func (db *DB) LoadTraceroute(dest string) (string, error) {
	var path string
	err := db.QueryRow(`SELECT path FROM traceroute WHERE dest = ?`, dest).Scan(&path)
	return path, err
}

func (db *DB) SaveTraceroute(dest, trace string) error {
	txn, err := db.Begin()
	if err != nil {
		return err
	}

	_, err = txn.Exec(`INSERT OR REPLACE INTO traceroute (dest, path) VALUES (?, ?)`, dest, trace)
	if err != nil {
		txn.Rollback()
		return err
	}

	return txn.Commit()
}
