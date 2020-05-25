package sqlite

import (
	"database/sql"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/jamesog/scan/pkg/scan"
)

// LoadJobs retrives the stored jobs.
func (db *DB) LoadJobs(filter SQLFilter) ([]scan.Job, error) {
	qry := fmt.Sprintf(`SELECT rowid, cidr, ports, proto, requested_by, submitted, received, count FROM job %s ORDER BY received DESC, submitted, rowid`, filter)
	rows, err := db.Query(qry, filter.Values...)
	if err != nil {
		log.Printf("loadJobs: error scanning table: %v\n", err)
		return []scan.Job{}, err
	}

	defer rows.Close()

	var id int
	var cidr, ports, proto, requestedBy string
	var submitted time.Time
	var received sql.NullTime
	var count sql.NullInt64

	var jobs []scan.Job

	for rows.Next() {
		err := rows.Scan(&id, &cidr, &ports, &proto, &requestedBy, &submitted, &received, &count)
		if err != nil {
			return []scan.Job{}, err
		}

		jobs = append(jobs, scan.Job{
			ID: id, CIDR: cidr, Ports: ports, Proto: proto,
			RequestedBy: requestedBy, Submitted: scan.Time{Time: submitted},
			Received: scan.Time{Time: received.Time}, Count: count.Int64})
	}

	return jobs, nil
}

// LoadJobSubmission retrieves the stored submissions associated with a job.
func (db *DB) LoadJobSubmission() (scan.Submission, error) {
	f := SQLFilter{
		Where: []string{"job_id IS NOT NULL"},
	}
	return db.LoadSubmission(f)
}

// SaveJob stores a new custom scan job request.
func (db *DB) SaveJob(cidr, ports, proto, user string) (int64, error) {
	txn, err := db.DB.Begin()
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

// UpdateJob updates the given job to mark the number of ports found.
func (db *DB) UpdateJob(id string, count int64) error {
	txn, err := db.DB.Begin()
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
