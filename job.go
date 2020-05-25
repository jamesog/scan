package main

import (
	"log"
	"net"
	"net/http"
	"strconv"
	"time"

	"github.com/go-chi/chi"
	"github.com/go-chi/render"
	"github.com/jamesog/scan/internal/sqlite"
	"github.com/jamesog/scan/pkg/scan"
	"github.com/prometheus/client_golang/prometheus"
)

type jobData struct {
	indexData
	JobID []string
	Jobs  []scan.Job
}

// Handler for GET and POST /job
func (app *App) newJob(w http.ResponseWriter, r *http.Request) {
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
		switch v := v.(type) {
		case string:
			user.Email = v
		case User:
			user = v
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
				id, err := app.db.SaveJob(cidr, ports, proto[i], user.Email)
				if err != nil {
					http.Error(w, err.Error(), http.StatusInternalServerError)
					return
				}
				jobID = append(jobID, strconv.FormatInt(id, 10))
			}
		}
	}

	jobs, err := app.db.LoadJobs(sqlite.SQLFilter{})
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	sub, err := app.db.LoadJobSubmission()
	if err != nil {
		log.Println("newJob: couldn't load submissions:", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Fetch result numbers for display in the navbar
	// Errors aren't fatal here, we can just display 0 results if something
	// goes wrong
	results, _ := app.db.ResultData("", "", "")

	data := jobData{
		indexData: indexData{
			Errors:        errors,
			Authenticated: true,
			User:          user,
			URI:           r.URL.Path,
			Submission:    sub,
			Data:          results,
		},
		JobID: jobID,
		Jobs:  jobs,
	}

	tmpl.ExecuteTemplate(w, "job", data)
}

// Handler for GET /jobs
func (app *App) jobs(w http.ResponseWriter, r *http.Request) {
	jobs, err := app.db.LoadJobs(sqlite.SQLFilter{
		Where: []string{"received IS NULL"},
	})
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		render.JSON(w, r, err.Error())
	}

	render.JSON(w, r, jobs)
}

// Handler for PUT /results/{id}
func (app *App) recvJobResults(w http.ResponseWriter, r *http.Request) {
	job := chi.URLParam(r, "id")

	// Check if the job ID is valid
	jobs, err := app.db.LoadJobs(sqlite.SQLFilter{
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
	count, err := app.saveResults(w, r, now)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Update the job
	err = app.db.UpdateJob(job, count)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	ip, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		ip = r.RemoteAddr
	}
	id, _ := strconv.ParseInt(job, 10, 64)

	err = app.db.SaveSubmission(ip, &id, now)
	if err != nil {
		log.Println("recvJobResults: error saving submission:", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Finally, update metrics
	gaugeJobSubmission.Set(float64(now.Unix()))
	gaugeJobs.With(prometheus.Labels{
		"id":        strconv.FormatInt(id, 10),
		"submitted": strconv.FormatInt(time.Now().Unix(), 10),
		"received":  strconv.FormatInt(time.Now().Unix(), 10),
	}).Set(float64(count))
}
