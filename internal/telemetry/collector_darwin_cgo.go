//go:build darwin && cgo

package telemetry

/*
#include <mach/mach.h>
#include <mach/mach_host.h>
#include <mach/host_info.h>
#include <mach/vm_statistics.h>

static int obacht_cpu_ticks(unsigned long long *user, unsigned long long *system,
                            unsigned long long *idle, unsigned long long *nice) {
    host_cpu_load_info_data_t info;
    mach_msg_type_number_t count = HOST_CPU_LOAD_INFO_COUNT;
    if (host_statistics(mach_host_self(), HOST_CPU_LOAD_INFO,
                        (host_info_t)&info, &count) != KERN_SUCCESS) {
        return -1;
    }
    *user   = info.cpu_ticks[CPU_STATE_USER];
    *system = info.cpu_ticks[CPU_STATE_SYSTEM];
    *idle   = info.cpu_ticks[CPU_STATE_IDLE];
    *nice   = info.cpu_ticks[CPU_STATE_NICE];
    return 0;
}

static int obacht_mem_used(unsigned long long *used) {
    vm_statistics64_data_t vm;
    mach_msg_type_number_t count = HOST_VM_INFO64_COUNT;
    if (host_statistics64(mach_host_self(), HOST_VM_INFO64,
                          (host_info64_t)&vm, &count) != KERN_SUCCESS) {
        return -1;
    }
    vm_size_t page = 0;
    host_page_size(mach_host_self(), &page);
    // macOS "Memory Used" ~= active + wired + compressed pages.
    *used = ((unsigned long long)vm.active_count +
             (unsigned long long)vm.wire_count +
             (unsigned long long)vm.compressor_page_count) * (unsigned long long)page;
    return 0;
}
*/
import "C"

import (
	"time"

	"golang.org/x/sys/unix"
)

// NewCollector returns the full macOS collector (native cgo build): CPU% and
// used RAM via Mach, plus total RAM, disk and network. CPU temperature needs
// the SMC (IOKit) and is left unset for now.
func NewCollector() Collector { return &darwinCollector{} }

type darwinCollector struct {
	prevTotal, prevIdle uint64
	hasPrev             bool
	net                 netInfo
}

func (c *darwinCollector) Collect() (Sample, error) {
	s := Sample{}

	if v, ok := c.cpuUsage(); ok {
		s.CPUUsage = &v
	}
	if total, err := unix.SysctlUint64("hw.memsize"); err == nil && total > 0 {
		s.RAMTotal = &total
		var used C.ulonglong
		if C.obacht_mem_used(&used) == 0 {
			u := uint64(used)
			if u > total {
				u = total
			}
			s.RAMUsed = &u
		}
	}
	if used, total, err := readDisk("/"); err == nil {
		s.DiskUsed = &used
		s.DiskTotal = &total
	}
	s.WireguardIP, s.LocalIP, s.PublicIP = c.net.collect()
	return s, nil
}

func cpuTicks() (total, idle uint64, ok bool) {
	var user, system, idl, nice C.ulonglong
	if C.obacht_cpu_ticks(&user, &system, &idl, &nice) != 0 {
		return 0, 0, false
	}
	return uint64(user) + uint64(system) + uint64(idl) + uint64(nice), uint64(idl), true
}

// cpuUsage returns 0..100 percent busy across all cores. The first call takes a
// quick 200ms sample; later calls diff against the previous (30s-ago) snapshot.
func (c *darwinCollector) cpuUsage() (float64, bool) {
	t1, i1, ok := cpuTicks()
	if !ok {
		return 0, false
	}
	if !c.hasPrev {
		time.Sleep(200 * time.Millisecond)
		t2, i2, ok2 := cpuTicks()
		if !ok2 {
			return 0, false
		}
		c.prevTotal, c.prevIdle, c.hasPrev = t2, i2, true
		return cpuPct(t1, i1, t2, i2), true
	}
	pct := cpuPct(c.prevTotal, c.prevIdle, t1, i1)
	c.prevTotal, c.prevIdle = t1, i1
	return pct, true
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
