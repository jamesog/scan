package main

import (
	"database/sql"
	"fmt"
	"log"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi"
	"github.com/go-chi/render"
	"github.com/prometheus/client_golang/prometheus"
)

type job struct {
	ID          int      `json:"id"`
	CIDR        string   `json:"cidr"`
	Ports       string   `json:"ports"`
	Proto       string   `json:"proto"`
	RequestedBy string   `json:"-"`
	Submitted   scanTime `json:"-"`
	Received    scanTime `json:"-"`
	Count       int64    `json:"-"`
}

func loadJobs(filter sqlFilter) ([]job, error) {
	qry := fmt.Sprintf(`SELECT rowid, cidr, ports, proto, requested_by, submitted, received, count FROM job %s ORDER BY received DESC, submitted, rowid`, filter)
	rows, err := db.Query(qry, filter.Values...)
	if err != nil {
		log.Printf("loadJobs: error scanning table: %v\n", err)
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

		jobs = append(jobs, job{id, cidr, ports, proto, requestedBy, scanTime(submitted), scanTime(received.Time), count.Int64})
	}

	return jobs, nil
}

func loadJobSubmission() (submission, error) {
	f := sqlFilter{
		Where: []string{"job_id IS NOT NULL"},
	}
	return loadSubmission(f)
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

	sub, err := loadJobSubmission()
	if err != nil {
		log.Println("newJob: couldn't load submissions:", err)
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
			Submission:    sub,
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

// Handler for PUT /results/{id}
func recvJobResults(w http.ResponseWriter, r *http.Request) {
	job := chi.URLParam(r, "id")

	// Check if the job ID is valid
	jobs, err := loadJobs(sqlFilter{
		Where:  []string{"rowid=?"},
		Values: []interface{}{job},
	})
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if len(jobs) == 0 {
		http.Error(w, "Job does not exist", http.StatusBadRequest)
		return
	}
	if !jobs[0].Received.IsZero() {
		http.Error(w, "Job already submitted", http.StatusBadRequest)
		return
	}

	now := time.Now().UTC()

	// Insert the results as normal
	count, err := saveResults(w, r, now)
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

	ip, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		ip = r.RemoteAddr
	}
	id, _ := strconv.ParseInt(job, 10, 64)

	err = saveSubmission(ip, &id, now)
	if err != nil {
		log.Println("recvJobResults: error saving submission:", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Finally, update metrics
	gaugeJobs.With(prometheus.Labels{
		"id":        strconv.FormatInt(id, 10),
		"submitted": strconv.FormatInt(time.Now().Unix(), 10),
		"received":  strconv.FormatInt(time.Now().Unix(), 10),
	}).Set(float64(count))
}
