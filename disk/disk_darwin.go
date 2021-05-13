// +build darwin

package disk

import (
	"fmt"
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
	output, err := exec.Command("iostat", "-d", "-c", "2", "-w", "1").Output()
	if err != nil {
		return nil, err
	}
	log.Debugf("iostat command output: %s", output)

	lines := strings.Split(string(output), "\n")
	line := strings.TrimSpace(lines[3])
	log.Debugf("Parsing iostat output line %s", line)
	var stats DiskStats
	stat := strings.Fields(line)
	if len(stat) < 3 {
		log.Debugf("iostat output line '%s' looks invalid (returned # of fields: %d), skipping it. ", line, len(stat))
		return nil, fmt.Errorf("iostat output line '%s' looks invalid (returned # of fields: %d), skipping it. ", line, len(stat))
	}
	kps, err := strconv.ParseFloat(stat[0], 10)
	if err != nil {
		log.Errorf("Could not parse iostat kps command output line: %s: %s", line, err)
		return nil, fmt.Errorf("Could not parse iostat kps command output line: %s: %s", line, err)
	}

	tps, err := strconv.ParseFloat(stat[1], 10)
	if err != nil {
		log.Errorf("Could not parse iostat tps command output line: %s: %s", line, err)
		return nil, fmt.Errorf("Could not parse iostat tps command output line: %s: %s", line, err)
	}

	mps, err := strconv.ParseFloat(stat[2], 10)
	if err != nil {
		log.Errorf("Could not parse iostat mbps command output line: %s: %s", line, err)
		return nil, fmt.Errorf("Could not parse iostat mbps command output line: %s: %s", line, err)
	}

	log.Debugf("iostats: %d, %d, %d", kps, tps, mps)

	stats.ReadsPerSecond += uint64(kps * tps * 1024)
	stats.WritesPerSecond += uint64(mps * 1024 * 1024)
	return &stats, nil
}
