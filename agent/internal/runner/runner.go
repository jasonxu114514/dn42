package runner

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strings"
	"time"
)

type Runner struct {
	BirdcPath string
	MtrPath   string
	PingPath  string
	Timeout   time.Duration
}

type Result struct {
	OK     bool   `json:"ok"`
	Output string `json:"output"`
}

var (
	dn42IPv4Net = parseCIDR("172.20.0.0/14")
	dn42IPv6Net = parseCIDR("fd00::/8")
)

func New() Runner {
	return Runner{
		BirdcPath: envOr("BIRDC_PATH", "birdc"),
		MtrPath:   envOr("MTR_PATH", "mtr"),
		PingPath:  envOr("PING_PATH", "ping"),
		Timeout:   12 * time.Second,
	}
}

func envOr(name, fallback string) string {
	if value := strings.TrimSpace(os.Getenv(name)); value != "" {
		return value
	}
	return fallback
}

func parseCIDR(value string) *net.IPNet {
	_, network, err := net.ParseCIDR(value)
	if err != nil {
		panic(err)
	}
	return network
}

func ValidateDN42IPTarget(target string) error {
	target = strings.TrimSpace(target)
	if target == "" || len(target) > 255 {
		return errors.New("invalid target length")
	}
	if hasUnsafeTargetChar(target) {
		return errors.New("target contains unsupported characters")
	}
	ip := net.ParseIP(target)
	if ip == nil {
		return errors.New("target must be a DN42 IP address")
	}
	if !isDN42IP(ip) {
		return errors.New("target must be inside DN42 address space")
	}
	return nil
}

func ValidateDN42RouteTarget(target string) error {
	target = strings.TrimSpace(target)
	if target == "" || len(target) > 255 {
		return errors.New("invalid target length")
	}
	if hasUnsafeTargetChar(target) {
		return errors.New("target contains unsupported characters")
	}
	if ip := net.ParseIP(target); ip != nil {
		if isDN42IP(ip) {
			return nil
		}
		return errors.New("target must be inside DN42 address space")
	}
	_, network, err := net.ParseCIDR(target)
	if err != nil {
		return errors.New("route target must be a DN42 IP address or CIDR prefix")
	}
	if !isDN42Prefix(network) {
		return errors.New("target must be inside DN42 address space")
	}
	return nil
}

func hasUnsafeTargetChar(target string) bool {
	if strings.HasPrefix(target, "-") {
		return true
	}
	for _, ch := range target {
		if ch < 33 || ch > 126 {
			return true
		}
		if strings.ContainsRune(";&|`$<>\\\"'(){}[]!*?", ch) {
			return true
		}
	}
	return false
}

func isDN42IP(ip net.IP) bool {
	return dn42IPv4Net.Contains(ip) || dn42IPv6Net.Contains(ip)
}

func isDN42Prefix(network *net.IPNet) bool {
	return containsPrefix(dn42IPv4Net, network) || containsPrefix(dn42IPv6Net, network)
}

func containsPrefix(parent *net.IPNet, child *net.IPNet) bool {
	return parent.Contains(child.IP) && parent.Contains(lastIP(child))
}

func lastIP(network *net.IPNet) net.IP {
	ip := network.IP
	if ip4 := ip.To4(); ip4 != nil {
		ip = ip4
	} else {
		ip = ip.To16()
	}

	last := make(net.IP, len(ip))
	copy(last, ip)
	for i := range last {
		last[i] |= ^network.Mask[i]
	}
	return last
}

func (r Runner) run(args ...string) Result {
	if len(args) == 0 {
		return Result{OK: false, Output: "missing command"}
	}
	ctx, cancel := context.WithTimeout(context.Background(), r.Timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, args[0], args[1:]...)
	out, err := cmd.CombinedOutput()
	output := string(out)
	if ctx.Err() == context.DeadlineExceeded {
		return Result{OK: false, Output: output + "\ncommand timed out"}
	}
	if err != nil {
		return Result{OK: false, Output: strings.TrimSpace(output + "\n" + err.Error())}
	}
	return Result{OK: true, Output: strings.TrimSpace(output)}
}

func (r Runner) Ping(target string) Result {
	if err := ValidateDN42IPTarget(target); err != nil {
		return Result{OK: false, Output: err.Error()}
	}
	return r.run(r.PingPath, "-c", "4", "-W", "3", target)
}

func (r Runner) MTR(target string) Result {
	if err := ValidateDN42IPTarget(target); err != nil {
		return Result{OK: false, Output: err.Error()}
	}
	return r.run(r.MtrPath, "-r", "-c", "5", "-w", target)
}

func (r Runner) Route(target string) Result {
	if err := ValidateDN42RouteTarget(target); err != nil {
		return Result{OK: false, Output: err.Error()}
	}
	return r.run(r.BirdcPath, "show", "route", target)
}

func (r Runner) Status() Result {
	bird := r.run(r.BirdcPath, "show", "protocols")
	if bird.OK {
		return bird
	}
	return Result{OK: false, Output: fmt.Sprintf("bird status failed:\n%s", bird.Output)}
}
