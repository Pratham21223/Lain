package config

import "time"

type Config struct {
	TargetURL   string
	RoutesFile  string
	Concurrency int
	Timeout     time.Duration
}

func Default() Config {
	return Config{
		Concurrency: 10,
		Timeout:     5 * time.Second,
	}
}
