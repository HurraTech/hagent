// +build linux

package disk

import (
	"time"

	"github.com/mackerelio/go-osstat/disk"
)

type DiskStats struct {
	ReadsPerSecond  uint64
	WritesPerSecond uint64
}

func Get() (*DiskStats, error) {
	before, err := disk.Get()
	if err != nil {
		return nil, err
	}
	time.Sleep(time.Duration(1) * time.Second)
	after, err := disk.Get()
	if err != nil {
		return nil, err
	}
	var before_total_reads uint64
	var before_total_writes uint64
	for _, disk := range before {
		before_total_reads += disk.ReadsCompleted
		before_total_writes += disk.WritesCompleted
	}

	var after_total_reads uint64
	var after_total_writes uint64
	for _, disk := range after {
		after_total_reads += disk.ReadsCompleted
		after_total_writes += disk.WritesCompleted
	}

	rps := after_total_reads - before_total_reads
	wps := after_total_writes - before_total_writes
	return &DiskStats{
		ReadsPerSecond:  rps,
		WritesPerSecond: wps,
	}, nil
}
