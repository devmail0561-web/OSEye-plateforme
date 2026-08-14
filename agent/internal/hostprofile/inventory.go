//go:build linux

package hostprofile

import (
	"bufio"
	"encoding/json"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
)

// HostInventory contains the hardware and software characteristics of the host.
// Sent to the server on first connection and periodically thereafter.
type HostInventory struct {
	Hostname              string   `json:"hostname"`
	OS                    string   `json:"os"`
	Arch                  string   `json:"arch"`
	NumCPU                int      `json:"num_cpu"`
	TotalMemMB            int64    `json:"total_mem_mb"`
	KernelVersion         string   `json:"kernel_version"`
	Distro                string   `json:"distro"`
	IsContainer           bool     `json:"is_container"`
	IsVM                  bool     `json:"is_vm"`
	ListeningPorts        []int    `json:"listening_ports"`
	ActiveServices        []string `json:"active_services"`
	InstalledPackageCount int      `json:"installed_packages_count"`
	SystemdUnitsActive    []string `json:"systemd_units_active"`
	UsersWithShell        []string `json:"users_with_shell"`
	UptimeSeconds         int64    `json:"uptime_seconds"`
}

// Collect gathers the current host inventory.
func Collect(hostname string) *HostInventory {
	inv := &HostInventory{
		Hostname: hostname,
		OS:       runtime.GOOS,
		Arch:     runtime.GOARCH,
		NumCPU:   runtime.NumCPU(),
	}

	inv.TotalMemMB = readTotalMemMB()
	inv.KernelVersion = readKernelVersion()
	inv.Distro = readDistro()
	inv.IsContainer = detectContainer()
	inv.IsVM = detectVM()
	inv.ListeningPorts = readListeningPorts()
	inv.ActiveServices = readActiveServices()
	inv.InstalledPackageCount = countInstalledPackages()
	inv.SystemdUnitsActive = readSystemdUnits()
	inv.UsersWithShell = readUsersWithShell()
	inv.UptimeSeconds = readUptime()

	return inv
}

// JSON returns the inventory as JSON bytes.
func (h *HostInventory) JSON() ([]byte, error) {
	return json.Marshal(h)
}

func readTotalMemMB() int64 {
	f, err := os.Open("/proc/meminfo")
	if err != nil {
		return 0
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "MemTotal:") {
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				kb, _ := strconv.ParseInt(fields[1], 10, 64)
				return kb / 1024
			}
		}
	}
	return 0
}

func readKernelVersion() string {
	data, err := os.ReadFile("/proc/version")
	if err != nil {
		return ""
	}
	fields := strings.Fields(string(data))
	if len(fields) >= 3 {
		return fields[2]
	}
	return ""
}

func readDistro() string {
	f, err := os.Open("/etc/os-release")
	if err != nil {
		return ""
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "PRETTY_NAME=") {
			val := strings.TrimPrefix(line, "PRETTY_NAME=")
			return strings.Trim(val, "\"")
		}
	}
	return ""
}

func detectContainer() bool {
	// Check for /.dockerenv or cgroup containing "docker" or "lxc".
	if _, err := os.Stat("/.dockerenv"); err == nil {
		return true
	}
	data, err := os.ReadFile("/proc/1/cgroup")
	if err != nil {
		return false
	}
	content := string(data)
	return strings.Contains(content, "docker") || strings.Contains(content, "lxc")
}

func detectVM() bool {
	data, err := os.ReadFile("/sys/class/dmi/id/product_name")
	if err != nil {
		return false
	}
	product := strings.ToLower(strings.TrimSpace(string(data)))
	vmIndicators := []string{"virtualbox", "vmware", "kvm", "qemu", "xen", "hyper-v", "bhyve"}
	for _, ind := range vmIndicators {
		if strings.Contains(product, ind) {
			return true
		}
	}
	return false
}

func readListeningPorts() []int {
	// Parse /proc/net/tcp and /proc/net/tcp6 for LISTEN state (0A).
	var ports []int
	seen := make(map[int]bool)

	for _, path := range []string{"/proc/net/tcp", "/proc/net/tcp6"} {
		f, err := os.Open(path)
		if err != nil {
			continue
		}
		scanner := bufio.NewScanner(f)
		scanner.Scan() // skip header
		for scanner.Scan() {
			fields := strings.Fields(scanner.Text())
			if len(fields) < 4 {
				continue
			}
			// State is field[3]; 0A = LISTEN.
			if fields[3] != "0A" {
				continue
			}
			// Local address is field[1] in hex:port format.
			parts := strings.Split(fields[1], ":")
			if len(parts) != 2 {
				continue
			}
			port, err := strconv.ParseInt(parts[1], 16, 32)
			if err != nil || port == 0 {
				continue
			}
			if !seen[int(port)] {
				seen[int(port)] = true
				ports = append(ports, int(port))
			}
		}
		f.Close()
	}
	return ports
}

func readActiveServices() []string {
	out, err := exec.Command("systemctl", "list-units", "--type=service", "--state=running", "--no-pager", "--plain", "--no-legend").Output()
	if err != nil {
		return nil
	}
	var services []string
	for _, line := range strings.Split(string(out), "\n") {
		fields := strings.Fields(line)
		if len(fields) >= 1 {
			name := strings.TrimSuffix(fields[0], ".service")
			if name != "" {
				services = append(services, name)
			}
		}
	}
	return services
}

func countInstalledPackages() int {
	// Try dpkg first, then rpm.
	if out, err := exec.Command("dpkg-query", "-f", ".\n", "-W").Output(); err == nil {
		return strings.Count(string(out), "\n")
	}
	if out, err := exec.Command("rpm", "-qa", "--qf", ".\n").Output(); err == nil {
		return strings.Count(string(out), "\n")
	}
	return 0
}

func readSystemdUnits() []string {
	out, err := exec.Command("systemctl", "list-units", "--type=service", "--state=running", "--no-pager", "--plain", "--no-legend").Output()
	if err != nil {
		return nil
	}
	var units []string
	for _, line := range strings.Split(string(out), "\n") {
		fields := strings.Fields(line)
		if len(fields) >= 1 && strings.HasSuffix(fields[0], ".service") {
			units = append(units, fields[0])
		}
	}
	return units
}

func readUsersWithShell() []string {
	f, err := os.Open("/etc/passwd")
	if err != nil {
		return nil
	}
	defer f.Close()

	noLoginShells := map[string]bool{
		"/usr/sbin/nologin": true,
		"/sbin/nologin":     true,
		"/bin/false":        true,
		"/usr/bin/false":    true,
	}

	var users []string
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		parts := strings.Split(scanner.Text(), ":")
		if len(parts) < 7 {
			continue
		}
		shell := parts[6]
		if shell != "" && !noLoginShells[shell] {
			users = append(users, parts[0])
		}
	}
	return users
}

func readUptime() int64 {
	data, err := os.ReadFile("/proc/uptime")
	if err != nil {
		return 0
	}
	fields := strings.Fields(string(data))
	if len(fields) >= 1 {
		sec, _ := strconv.ParseFloat(fields[0], 64)
		return int64(sec)
	}
	return 0
}
