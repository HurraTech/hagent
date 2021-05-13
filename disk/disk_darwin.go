// +build darwin
package disk

import (
	"os/exec"
	"strconv"
	"strings"

	log "github.com/sirupsen/logrus"
)

// Stats represents disk I/O statistics for linux.
type DiskStats struct {
	ReadsPerSecond  uint64
	WritesPerSecond uint64
}

func Get() (*DiskStats, error) {
	output, err := exec.Command("iostat", "-d").Output()
	if err != nil {
		return nil, err
	}
	log.Debugf("iostat command output: %s", output)

	lines := strings.Split(string(output), "\n")
	var stats DiskStats
	for _, line := range lines[2:] {
		line = strings.TrimSpace(line)
		log.Debugf("Parsing iostat output line %s", line)
		stat := strings.Fields(line)
		if len(stat) < 3 {
			log.Debugf("iostat output line '%s' looks invalid (returned # of fields: %d), skipping it. ", line, len(stat))
			continue
		}
		kps, err := strconv.ParseFloat(stat[0], 10)
		if err != nil {
			log.Errorf("Could not parse iostat kps command output line: %s: %s", line, err)
			continue
		}

		tps, err := strconv.ParseFloat(stat[1], 10)
		if err != nil {
			log.Errorf("Could not parse iostat tps command output line: %s: %s", line, err)
			continue
		}

		mps, err := strconv.ParseFloat(stat[2], 10)
		if err != nil {
			log.Errorf("Could not parse iostat mbps command output line: %s: %s", line, err)
			continue
		}

		log.Infof("iostats: %d, %d, %d", kps, tps, mps)

		stats.ReadsPerSecond += uint64(kps * tps * 1024)
		stats.WritesPerSecond += uint64(mps * 1024 * 1024)
	}
	return &stats, nil
}
