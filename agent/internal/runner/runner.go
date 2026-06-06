package runner

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

type Runner struct {
	BirdcPath        string
	MtrPath          string
	PingPath         string
	WgQuickPath      string
	Timeout          time.Duration
	WireGuardPeerDir string
	BirdPeerDir      string
	DeployReloadCmd  string
	WireGuardKey     string
}

type Result struct {
	OK     bool   `json:"ok"`
	Output string `json:"output"`
}

type DeployRequest struct {
	RequestID       int    `json:"request_id"`
	ASN             string `json:"asn"`
	Node            string `json:"node"`
	ProtocolName    string `json:"protocol_name"`
	WireGuardConfig string `json:"wireguard_config"`
	BirdConfig      string `json:"bird_config"`
}

type DeployResult struct {
	OK      bool     `json:"ok"`
	Applied bool     `json:"applied"`
	Output  string   `json:"output"`
	Files   []string `json:"files"`
}

var (
	dn42IPv4Net = parseCIDR("172.20.0.0/14")
	dn42IPv6Net = parseCIDR("fd00::/8")
	safeNameRE  = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9_-]{0,79}$`)
)

func New() Runner {
	deployDir := envOr("AGENT_DEPLOY_DIR", "/etc/dn42-autopeer")
	return Runner{
		BirdcPath:        envOr("BIRDC_PATH", "birdc"),
		MtrPath:          envOr("MTR_PATH", "mtr"),
		PingPath:         envOr("PING_PATH", "ping"),
		WgQuickPath:      envOr("WG_QUICK_PATH", "wg-quick"),
		Timeout:          12 * time.Second,
		WireGuardPeerDir: envOr("WIREGUARD_PEER_DIR", filepath.Join(deployDir, "wireguard")),
		BirdPeerDir:      envOr("BIRD_PEER_DIR", filepath.Join(deployDir, "bird")),
		DeployReloadCmd:  strings.TrimSpace(os.Getenv("AGENT_DEPLOY_RELOAD_CMD")),
		WireGuardKey:     strings.TrimSpace(os.Getenv("WIREGUARD_PRIVATE_KEY")),
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

func (r Runner) DeployPeer(req DeployRequest) DeployResult {
	req.ASN = strings.TrimSpace(req.ASN)
	req.Node = strings.TrimSpace(req.Node)
	req.ProtocolName = strings.TrimSpace(req.ProtocolName)
	req.WireGuardConfig = strings.TrimSpace(req.WireGuardConfig)
	req.BirdConfig = strings.TrimSpace(req.BirdConfig)
	if err := validateDeployRequest(req); err != nil {
		return DeployResult{OK: false, Applied: false, Output: err.Error()}
	}

	files := []string{
		filepath.Join(r.WireGuardPeerDir, req.ProtocolName+".conf"),
		filepath.Join(r.BirdPeerDir, req.ProtocolName+".conf"),
	}
	wireGuardConfig, err := r.renderWireGuardConfig(req.WireGuardConfig)
	if err != nil {
		return DeployResult{OK: false, Output: err.Error(), Files: files}
	}

	if err := ensureChildPath(r.WireGuardPeerDir, files[0]); err != nil {
		return DeployResult{OK: false, Output: err.Error()}
	}
	if err := ensureChildPath(r.BirdPeerDir, files[1]); err != nil {
		return DeployResult{OK: false, Output: err.Error()}
	}
	if err := writeConfigFile(files[0], wireGuardConfig+"\n"); err != nil {
		return DeployResult{OK: false, Output: err.Error(), Files: files}
	}
	if err := writeConfigFile(files[1], req.BirdConfig+"\n"); err != nil {
		return DeployResult{OK: false, Output: err.Error(), Files: files}
	}

	output := "deployed peer config"
	down := r.run(r.WgQuickPath, "down", files[0])
	if down.Output != "" {
		output = strings.TrimSpace(output + "\nwg-quick down:\n" + down.Output)
	}
	up := r.run(r.WgQuickPath, "up", files[0])
	output = strings.TrimSpace(output + "\nwg-quick up:\n" + up.Output)
	if !up.OK {
		return DeployResult{OK: false, Applied: true, Output: output, Files: files}
	}
	if r.DeployReloadCmd != "" {
		reload := r.run(strings.Fields(r.DeployReloadCmd)...)
		output = strings.TrimSpace(output + "\n" + reload.Output)
		if !reload.OK {
			return DeployResult{OK: false, Applied: true, Output: output, Files: files}
		}
	}
	return DeployResult{OK: true, Applied: true, Output: output, Files: files}
}

func (r Runner) renderWireGuardConfig(config string) (string, error) {
	const placeholder = "{{WIREGUARD_PRIVATE_KEY}}"
	if strings.Contains(config, placeholder) {
		if r.WireGuardKey == "" {
			return "", errors.New("WIREGUARD_PRIVATE_KEY is required for WireGuard deployment")
		}
		return strings.ReplaceAll(config, placeholder, r.WireGuardKey), nil
	}
	return config, nil
}

func validateDeployRequest(req DeployRequest) error {
	if req.RequestID <= 0 {
		return errors.New("request_id is required")
	}
	if req.ASN == "" || len(req.ASN) > 32 || hasUnsafeTargetChar(req.ASN) {
		return errors.New("invalid asn")
	}
	if req.Node == "" || len(req.Node) > 64 || strings.ContainsAny(req.Node, "/\\") {
		return errors.New("invalid node")
	}
	if !safeNameRE.MatchString(req.ProtocolName) {
		return errors.New("invalid protocol_name")
	}
	if err := validateConfigSnippet("wireguard_config", req.WireGuardConfig); err != nil {
		return err
	}
	if err := validateConfigSnippet("bird_config", req.BirdConfig); err != nil {
		return err
	}
	return nil
}

func validateConfigSnippet(name string, value string) error {
	if value == "" {
		return fmt.Errorf("%s is required", name)
	}
	if len(value) > 16*1024 {
		return fmt.Errorf("%s is too large", name)
	}
	if strings.ContainsRune(value, '\x00') {
		return fmt.Errorf("%s contains invalid data", name)
	}
	return nil
}

func ensureChildPath(parent string, child string) error {
	parentAbs, err := filepath.Abs(parent)
	if err != nil {
		return err
	}
	childAbs, err := filepath.Abs(child)
	if err != nil {
		return err
	}
	rel, err := filepath.Rel(parentAbs, childAbs)
	if err != nil {
		return err
	}
	if rel == "." || strings.HasPrefix(rel, ".."+string(os.PathSeparator)) || rel == ".." {
		return fmt.Errorf("refusing to write outside %s", parentAbs)
	}
	return nil
}

func writeConfigFile(path string, content string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0750); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".autopeer-*.tmp")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if _, err := tmp.WriteString(content); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Chmod(0640); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpName, path)
}
