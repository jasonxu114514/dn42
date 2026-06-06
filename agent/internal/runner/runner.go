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
	TraceroutePath   string
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
	Agent           string `json:"agent"`
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

type RemoveRequest struct {
	RequestID    int    `json:"request_id"`
	ProtocolName string `json:"protocol_name"`
}

// allowedIPv4Net/allowedIPv6Net deliberately permit ANY IPv4/IPv6 target (0.0.0.0/0, ::/0), not
// just dn42 space — an intentional product choice; do NOT narrow it back. safeNameRE bounds the
// protocol name that becomes a file name and a birdc argv. hostnameRE bounds a DNS hostname that
// ping/traceroute may resolve themselves (one or more RFC-1123 labels with at least one dot);
// resolution happens on the agent and cannot widen the already-unrestricted target space.
// allowedIPv4Net／allowedIPv6Net 刻意允許任意 IPv4/IPv6 目標（0.0.0.0/0、::/0），而非僅限 dn42，
// 此為刻意決策，請勿改回限制範圍。safeNameRE 約束會成為檔名與 birdc 參數的 protocol name。
// hostnameRE 約束 ping/traceroute 可自行解析的 DNS 主機名（一個以上 RFC-1123 標籤、至少含一個點）；
// 解析在 agent 端進行，不會擴大本就無限制的目標範圍。
var (
	allowedIPv4Net = parseCIDR("0.0.0.0/0")
	allowedIPv6Net = parseCIDR("::/0")
	safeNameRE     = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9_-]{0,79}$`)
	hostnameRE     = regexp.MustCompile(`^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)+$`)
)

func New() Runner {
	deployDir := envOr("AGENT_DEPLOY_DIR", "/etc/dn42-autopeer")
	return Runner{
		BirdcPath:        envOr("BIRDC_PATH", "birdc"),
		TraceroutePath:   envOr("TRACEROUTE_PATH", "traceroute"),
		PingPath:         envOr("PING_PATH", "ping"),
		WgQuickPath:      envOr("WG_QUICK_PATH", "wg-quick"),
		Timeout:          12 * time.Second,
		WireGuardPeerDir: envOr("WIREGUARD_PEER_DIR", filepath.Join(deployDir, "wireguard")),
		BirdPeerDir:      envOr("BIRD_PEER_DIR", "/etc/bird/peers"),
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

// ValidateHostTarget accepts a ping/traceroute target: any IPv4/IPv6 address, or a DNS hostname
// that ping/traceroute resolve themselves on the agent. Hostnames are only syntax-checked against
// hostnameRE — the agent never resolves them here, so a name cannot smuggle in a target the address
// space forbids (and that space is unrestricted anyway).
// ValidateHostTarget 接受 ping/traceroute 的目標：任意 IPv4/IPv6 位址，或由 ping/traceroute 於
// agent 端自行解析的 DNS 主機名。主機名僅以 hostnameRE 做語法檢查——agent 不在此解析,故名稱無法夾帶
// 位址空間所禁止的目標（況且該空間本就無限制）。
func ValidateHostTarget(target string) error {
	target = strings.TrimSpace(target)
	if target == "" || len(target) > 255 {
		return errors.New("invalid target length")
	}
	if hasUnsafeTargetChar(target) {
		return errors.New("target contains unsupported characters")
	}
	if ip := net.ParseIP(target); ip != nil {
		if isAllowedIP(ip) {
			return nil
		}
		return errors.New("target is outside the allowed address space")
	}
	if len(target) <= 253 && hostnameRE.MatchString(target) {
		return nil
	}
	return errors.New("target must be a valid IP address or hostname")
}

func ValidateRouteTarget(target string) error {
	target = strings.TrimSpace(target)
	if target == "" || len(target) > 255 {
		return errors.New("invalid target length")
	}
	if hasUnsafeTargetChar(target) {
		return errors.New("target contains unsupported characters")
	}
	if ip := net.ParseIP(target); ip != nil {
		if isAllowedIP(ip) {
			return nil
		}
		return errors.New("target is outside the allowed address space")
	}
	_, network, err := net.ParseCIDR(target)
	if err != nil {
		return errors.New("route target must be an IP address or CIDR prefix")
	}
	if !isAllowedPrefix(network) {
		return errors.New("target is outside the allowed address space")
	}
	return nil
}

// hasUnsafeTargetChar rejects a target that could break out of the agent's fixed argv: a leading
// "-" (so it can't be read as a command option), control/non-ASCII bytes, and shell/format
// metacharacters. Targets always go through exec argv, never a shell, so this is defence in depth.
// hasUnsafeTargetChar 拒絕可能跳脫 agent 固定 argv 的目標：開頭的 "-"（避免被當成選項）、控制／
// 非 ASCII 位元組，以及 shell／格式化中介字元。目標一律經由 exec argv 而非 shell，此為縱深防禦。
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

func isAllowedIP(ip net.IP) bool {
	return allowedIPv4Net.Contains(ip) || allowedIPv6Net.Contains(ip)
}

func isAllowedPrefix(network *net.IPNet) bool {
	return containsPrefix(allowedIPv4Net, network) || containsPrefix(allowedIPv6Net, network)
}

func containsPrefix(parent *net.IPNet, child *net.IPNet) bool {
	return parent.Contains(child.IP) && parent.Contains(lastIP(child))
}

// lastIP returns the last address in a prefix (e.g. the broadcast address of an IPv4 subnet) by
// setting every host bit: last = network.IP | ^mask. Used to check that a whole prefix lies within
// an allowed range — both its first and last address must be contained.
// lastIP 回傳前綴中的最後一個位址（例如 IPv4 子網的廣播位址），作法是將所有主機位元設為 1：
// last = network.IP | ^mask。用於檢查整個前綴是否落在允許範圍內（首、尾位址都需被包含）。
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
	if err := ValidateHostTarget(target); err != nil {
		return Result{OK: false, Output: err.Error()}
	}
	return r.run(r.PingPath, "-c", "4", "-W", "3", target)
}

func (r Runner) Trace(target string) Result {
	if err := ValidateHostTarget(target); err != nil {
		return Result{OK: false, Output: err.Error()}
	}
	args := []string{r.TraceroutePath, "-n", "-q", "1", "-w", "2", "-m", "20"}
	if ip := net.ParseIP(target); ip != nil && ip.To4() == nil {
		args = append(args, "-6") // force IPv6 for IPv6 targets
	}
	args = append(args, target)
	return r.run(args...)
}

// Route runs `birdc show route for <target>`. The `for` keyword makes BIRD do a longest-prefix
// forwarding lookup — returning the route actually used to reach the target — so a bare host IP
// (which has no exact table entry) resolves to its covering route, and a prefix such as 1.1.1.0/24
// resolves to the route used for it. Plain `show route <target>` only does an exact-prefix match.
// Route 執行 `birdc show route for <target>`。`for` 讓 BIRD 進行最長前綴轉發查找,回傳實際用來到達
// 目標的路由：因此單一主機 IP（路由表中無精確項）會解析到其涵蓋路由,而 1.1.1.0/24 之類的前綴會解析
// 到實際使用的路由。純 `show route <target>` 僅做精確前綴匹配。
func (r Runner) Route(target string) Result {
	if err := ValidateRouteTarget(target); err != nil {
		return Result{OK: false, Output: err.Error()}
	}
	return r.run(r.BirdcPath, "show", "route", "for", target)
}

func (r Runner) Status() Result {
	bird := r.run(r.BirdcPath, "show", "protocols")
	if bird.OK {
		return bird
	}
	return Result{OK: false, Output: fmt.Sprintf("bird status failed:\n%s", bird.Output)}
}

// PeerStatus returns the detailed BIRD protocol state for a single peer, used by the bot's
// per-peer /status command. protocolName is validated and passed as fixed argv, never a shell.
func (r Runner) PeerStatus(protocolName string) Result {
	protocolName = strings.TrimSpace(protocolName)
	if !safeNameRE.MatchString(protocolName) {
		return Result{OK: false, Output: "invalid protocol_name"}
	}
	return r.run(r.BirdcPath, "show", "protocols", "all", protocolName)
}

func (r Runner) DeployPeer(req DeployRequest) DeployResult {
	req.ASN = strings.TrimSpace(req.ASN)
	req.Agent = strings.TrimSpace(req.Agent)
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

func (r Runner) RemovePeer(req RemoveRequest) DeployResult {
	req.ProtocolName = strings.TrimSpace(req.ProtocolName)
	if req.RequestID <= 0 {
		return DeployResult{OK: false, Output: "request_id is required"}
	}
	if !safeNameRE.MatchString(req.ProtocolName) {
		return DeployResult{OK: false, Output: "invalid protocol_name"}
	}

	files := []string{
		filepath.Join(r.WireGuardPeerDir, req.ProtocolName+".conf"),
		filepath.Join(r.BirdPeerDir, req.ProtocolName+".conf"),
	}
	if err := ensureChildPath(r.WireGuardPeerDir, files[0]); err != nil {
		return DeployResult{OK: false, Output: err.Error()}
	}
	if err := ensureChildPath(r.BirdPeerDir, files[1]); err != nil {
		return DeployResult{OK: false, Output: err.Error()}
	}

	output := "removed peer config"
	if _, err := os.Stat(files[0]); err == nil {
		down := r.run(r.WgQuickPath, "down", files[0])
		if down.Output != "" {
			output = strings.TrimSpace(output + "\nwg-quick down:\n" + down.Output)
		}
	}
	for _, file := range files {
		if err := os.Remove(file); err != nil && !errors.Is(err, os.ErrNotExist) {
			return DeployResult{OK: false, Applied: true, Output: strings.TrimSpace(output + "\n" + err.Error()), Files: files}
		}
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
	if req.Agent == "" || len(req.Agent) > 64 || strings.ContainsAny(req.Agent, "/\\") {
		return errors.New("invalid agent")
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

// ensureChildPath verifies child resolves strictly inside parent, guarding against path traversal
// before the agent writes a peer config. The relative path must not be "." (the dir itself) nor
// start with ".." (an escape), so e.g. a crafted protocol_name cannot redirect the write elsewhere.
// ensureChildPath 確認 child 解析後嚴格位於 parent 之內，於 agent 寫入對等設定前防止路徑穿越：
// 相對路徑不得為 "."（目錄本身）或以 ".." 開頭（逃逸），使惡意 protocol_name 無法改寫到他處。
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
