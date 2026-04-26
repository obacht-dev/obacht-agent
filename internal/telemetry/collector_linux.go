//go:build linux

package telemetry

import (
	"bufio"
	"errors"
	"os"
	"strconv"
	"strings"
	"time"

	"golang.org/x/sys/unix"
)

// NewCollector returns a Linux /proc + /sys based collector.
func NewCollector() Collector { return &linuxCollector{} }

type linuxCollector struct {
	// Cached previous CPU snapshot for delta calculation across calls.
	prevTotal, prevIdle uint64
	hasPrev             bool
}

func (c *linuxCollector) Collect() (Sample, error) {
	s := Sample{}

	if v, err := readCPUUsage(c); err == nil {
		s.CPUUsage = &v
	}
	if used, total, err := readMem(); err == nil {
		s.RAMUsed = &used
		s.RAMTotal = &total
	}
	if used, total, err := readDisk("/"); err == nil {
		s.DiskUsed = &used
		s.DiskTotal = &total
	}
	if t, err := readTempCPU(); err == nil {
		s.TempCPU = &t
	}
	return s, nil
}

// readCPUUsage reads /proc/stat twice (current call + cached previous, or a
// short 200ms sample on first call) and returns 0..100 percent busy.
func readCPUUsage(c *linuxCollector) (float64, error) {
	total1, idle1, err := readCPUStat()
	if err != nil {
		return 0, err
	}
	if !c.hasPrev {
		// First call ever — take a quick second sample so we have something
		// useful immediately. Subsequent calls reuse the previous snapshot.
		time.Sleep(200 * time.Millisecond)
		total2, idle2, err := readCPUStat()
		if err != nil {
			return 0, err
		}
		c.prevTotal, c.prevIdle, c.hasPrev = total2, idle2, true
		return cpuPct(total1, idle1, total2, idle2), nil
	}
	pct := cpuPct(c.prevTotal, c.prevIdle, total1, idle1)
	c.prevTotal, c.prevIdle = total1, idle1
	return pct, nil
}

func cpuPct(t1, i1, t2, i2 uint64) float64 {
	dt := int64(t2) - int64(t1)
	di := int64(i2) - int64(i1)
	if dt <= 0 {
		return 0
	}
	busy := dt - di
	if busy < 0 {
		busy = 0
	}
	return float64(busy) * 100.0 / float64(dt)
}

func readCPUStat() (total, idle uint64, err error) {
	f, err := os.Open("/proc/stat")
	if err != nil {
		return 0, 0, err
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	if !sc.Scan() {
		return 0, 0, errors.New("empty /proc/stat")
	}
	// "cpu  user nice system idle iowait irq softirq steal guest guest_nice"
	fields := strings.Fields(sc.Text())
	if len(fields) < 5 || fields[0] != "cpu" {
		return 0, 0, errors.New("malformed /proc/stat header")
	}
	for i := 1; i < len(fields); i++ {
		v, _ := strconv.ParseUint(fields[i], 10, 64)
		total += v
		if i == 4 { // idle column
			idle = v
		}
	}
	return total, idle, nil
}

func readMem() (used, total uint64, err error) {
	f, err := os.Open("/proc/meminfo")
	if err != nil {
		return 0, 0, err
	}
	defer f.Close()
	var memTotal, memAvail uint64
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		switch {
		case strings.HasPrefix(line, "MemTotal:"):
			memTotal = parseMeminfoKB(line)
		case strings.HasPrefix(line, "MemAvailable:"):
			memAvail = parseMeminfoKB(line)
		}
		if memTotal > 0 && memAvail > 0 {
			break
		}
	}
	if memTotal == 0 {
		return 0, 0, errors.New("MemTotal not found")
	}
	if memAvail > memTotal {
		memAvail = memTotal
	}
	return (memTotal - memAvail) * 1024, memTotal * 1024, nil
}

func parseMeminfoKB(line string) uint64 {
	fields := strings.Fields(line)
	if len(fields) < 2 {
		return 0
	}
	v, _ := strconv.ParseUint(fields[1], 10, 64)
	return v
}

func readDisk(path string) (used, total uint64, err error) {
	var st unix.Statfs_t
	if err := unix.Statfs(path, &st); err != nil {
		return 0, 0, err
	}
	bsize := uint64(st.Bsize)
	total = st.Blocks * bsize
	free := st.Bavail * bsize
	if free > total {
		free = total
	}
	return total - free, total, nil
}

func readTempCPU() (float64, error) {
	b, err := os.ReadFile("/sys/class/thermal/thermal_zone0/temp")
	if err != nil {
		return 0, err
	}
	v, err := strconv.ParseFloat(strings.TrimSpace(string(b)), 64)
	if err != nil {
		return 0, err
	}
	return v / 1000.0, nil
}
