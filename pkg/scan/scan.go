package scan

import (
	"time"
)

// Port is a masscan port description.
type Port struct {
	Port    int    `json:"port"`
	Proto   string `json:"proto"`
	Status  string `json:"status"`
	Service struct {
		Name   string `json:"name"`
		Banner string `json:"banner"`
	} `json:"service"`
}

// Result data posted from masscan.
type Result struct {
	IP    string `json:"ip"`
	Ports []Port `json:"ports"`
}

// Time wraps time.Time to implement a custom String method.
type Time struct {
	time.Time
}

const dateTime = "2006-01-02 15:04"

func (t Time) String() string {
	if t.IsZero() {
		return ""
	}
	return t.Format(dateTime)
}

// IPInfo is data retrieved from the database for display.
type IPInfo struct {
	IP            string
	Port          int
	Proto         string
	FirstSeen     Time
	LastSeen      Time
	New           bool
	Gone          bool
	HasTraceroute bool
}

// Data is used for display in the UI. It contains a summary of the number of
// items stored in the database as well as each result.
type Data struct {
	Total    int
	Latest   int
	New      int
	LastSeen int64
	Results  []IPInfo
}

// Submission is used for display in the UI to show when and which host last
// submitted results.
type Submission struct {
	Host string
	Job  int64
	Time Time
}

// Job represents a job to be sent to and received from scanning nodes,
type Job struct {
	ID          int    `json:"id"`
	CIDR        string `json:"cidr"`
	Ports       string `json:"ports"`
	Proto       string `json:"proto"`
	RequestedBy string `json:"-"`
	Submitted   Time   `json:"-"`
	Received    Time   `json:"-"`
	Count       int64  `json:"-"`
}
