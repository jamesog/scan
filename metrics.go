package main

import (
	"net/http"
	"strconv"

	"github.com/jamesog/scan/internal/sqlite"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

var (
	gaugeTotal = prometheus.NewGauge(prometheus.GaugeOpts{
		Namespace: "scan",
		Subsystem: "ips",
		Name:      "total",
		Help:      "Total IPs found",
	})

	gaugeLatest = prometheus.NewGauge(prometheus.GaugeOpts{
		Namespace: "scan",
		Subsystem: "ips",
		Name:      "latest",
		Help:      "Latest IPs found",
	})

	gaugeNew = prometheus.NewGauge(prometheus.GaugeOpts{
		Namespace: "scan",
		Subsystem: "ips",
		Name:      "new",
		Help:      "New IPs found",
	})

	gaugeSubmission = prometheus.NewGauge(prometheus.GaugeOpts{
		Namespace: "scan",
		Name:      "last_submission_time",
		Help:      "Last submission time in seconds since the Unix epoch",
	})

	gaugeJobs = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Namespace: "scan",
			Name:      "job",
			Help:      "Number of IPs found in each each job, with submitted and received times",
		},
		[]string{"id", "submitted", "received"})

	gaugeJobSubmission = prometheus.NewGauge(prometheus.GaugeOpts{
		Namespace: "scan",
		Subsystem: "job",
		Name:      "last_submission_time",
		Help:      "Last job submission time in seconds since the Unix epoch",
	})
)

func init() {
	prometheus.MustRegister(gaugeTotal)
	prometheus.MustRegister(gaugeLatest)
	prometheus.MustRegister(gaugeNew)
	prometheus.MustRegister(gaugeSubmission)
	prometheus.MustRegister(gaugeJobs)
	prometheus.MustRegister(gaugeJobSubmission)
}

func (app *App) metrics() http.Handler {
	results, err := app.db.ResultData("", "", "")
	if err == nil {
		gaugeTotal.Set(float64(results.Total))
		gaugeLatest.Set(float64(results.Latest))
		gaugeNew.Set(float64(results.New))
	}

	jobs, _ := app.db.LoadJobs(sqlite.SQLFilter{
		Where: []string{`received IS NOT NULL`},
	})
	for _, job := range jobs {
		gaugeJobs.With(prometheus.Labels{
			"id":        strconv.Itoa(job.ID),
			"submitted": strconv.FormatInt(job.Submitted.Unix(), 10),
			"received":  strconv.FormatInt(job.Received.Unix(), 10),
		}).Set(float64(job.Count))
	}

	sub, _ := app.db.LoadSubmission(sqlite.SQLFilter{})
	gaugeSubmission.Set(float64(sub.Time.Unix()))

	return promhttp.Handler()
}
