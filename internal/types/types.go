package types

import "time"

type Route struct {
	Method string
	Path   string
	Params []string
}

type Finding struct {
	ID       string
	Title    string
	Severity string
	VulnType string
	Route    Route
	Param    string
	Payload  string
	Evidence string
	Location string
}

type ScanResult struct {
	Findings       []Finding
	TargetsScanned int
	StartedAt      time.Time
	FinishedAt     time.Time
}
