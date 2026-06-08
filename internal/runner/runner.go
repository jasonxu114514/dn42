package runner

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"dn42-autopeer-node/internal/config"
)

type Runner struct {
	BirdcPath        string
	TraceroutePath   string
	MtrPath          string
	PingPath         string
	WgPath           string
	WgQuickPath      string
	Timeout          time.Duration
	WireGuardPeerDir string
	BirdPeerDir      string
	BirdPeerGroup    string
	DeployReloadCmd  string
	WireGuardKey     string
	WireGuardPubKey  string
}

type Result struct {
	OK     bool   `json:"ok"`
	Output string `json:"output"`
}

type DeployRequest struct {
	RequestID       string `json:"request_id"`
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

type RemoveRequest struct {
	RequestID    string `json:"request_id"`
	ProtocolName string `json:"protocol_name"`
}

// allowedIPv4Net/allowedIPv6Net deliberately permit ANY IPv4/IPv6 target (0.0.0.0/0, ::/0), not
// just dn42 space — an intentional product choice; do NOT narrow it back. safeNameRE bounds the
// protocol name that becomes a file name and a birdc argv. hostnameRE bounds a DNS hostname that
// ping/traceroute may resolve themselves (one or more RFC-1123 labels with at least one dot);
// resolution happens on the node service and cannot widen the already-unrestricted target space.
// allowedIPv4Net／allowedIPv6Net 刻意允許任意 IPv4/IPv6 目標（0.0.0.0/0、::/0），而非僅限 dn42，
// 此為刻意決策，請勿改回限制範圍。safeNameRE 約束會成為檔名與 birdc 參數的 protocol name。
// hostnameRE 約束 ping/traceroute 可自行解析的 DNS 主機名（一個以上 RFC-1123 標籤、至少含一個點）；
// 解析在 node service 端進行，不會擴大本就無限制的目標範圍。
var (
	allowedIPv4Net = parseCIDR("0.0.0.0/0")
	allowedIPv6Net = parseCIDR("::/0")
	safeNameRE     = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9_-]{0,79}$`)
	hostnameRE     = regexp.MustCompile(`^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)+$`)
	wgKeyRE        = regexp.MustCompile(`^[A-Za-z0-9+/]{43}=$`)
)

// New builds a Runner from the loaded config. The WireGuard peer directory defaults to
// /etc/wireguard (wg-quick's conventional location) via config defaults; deployed peer files are
// still addressed by their full path, so a non-default wireguard_peer_dir keeps working.
// New 依載入的設定建立 Runner。WireGuard 對等目錄透過設定預設為 /etc/wireguard(wg-quick 的慣用位置);
// 部署的對等檔仍以完整路徑定位,故將 wireguard_peer_dir 設為非預設值也能運作。
func New(cfg config.Config) Runner {
	return Runner{
		BirdcPath:        cfg.BirdcPath,
		TraceroutePath:   cfg.TraceroutePath,
		MtrPath:          cfg.MtrPath,
		PingPath:         cfg.PingPath,
		WgPath:           cfg.WgPath,
		WgQuickPath:      cfg.WgQuickPath,
		Timeout:          cfg.Timeout(),
		WireGuardPeerDir: cfg.WireGuardPeerDir,
		BirdPeerDir:      cfg.BirdPeerDir,
		BirdPeerGroup:    cfg.BirdGroup(),
		DeployReloadCmd:  cfg.DeployReloadCmd,
		WireGuardKey:     cfg.WireGuardPrivateKey,
		WireGuardPubKey:  cfg.WireGuardPublicKey,
	}
}

// ValidWireGuardKey reports whether s is a syntactically valid base64 WireGuard key (32 bytes ->
// 43 base64 chars + "="). The node service's own public key is served to peers verbatim, so the operator
// must supply a well-formed value; this is the same shape the backend enforces for peer keys.
// ValidWireGuardKey 判斷 s 是否為語法正確的 base64 WireGuard 金鑰（32 bytes → 43 個 base64 字元加
// 一個 "="）。node service 自身的公鑰會原樣提供給對等端，故操作者必須給定格式正確的值；此格式與後端對
// 對等端金鑰的要求一致。
func ValidWireGuardKey(s string) bool {
	return wgKeyRE.MatchString(strings.TrimSpace(s))
}

func parseCIDR(value string) *net.IPNet {
	_, network, err := net.ParseCIDR(value)
	if err != nil {
		panic(err)
	}
	return network
}

// ValidateHostTarget accepts a ping/traceroute target: any IPv4/IPv6 address, or a DNS hostname
// that ping/traceroute resolve themselves on the node service. Hostnames are only syntax-checked against
// hostnameRE — the node service never resolves them here, so a name cannot smuggle in a target the address
// space forbids (and that space is unrestricted anyway).
// ValidateHostTarget 接受 ping/traceroute 的目標：任意 IPv4/IPv6 位址，或由 ping/traceroute 於
// node service 端自行解析的 DNS 主機名。主機名僅以 hostnameRE 做語法檢查——node service 不在此解析,故名稱無法夾帶
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

// hasUnsafeTargetChar rejects a target that could break out of the node service's fixed argv: a leading
// "-" (so it can't be read as a command option), control/non-ASCII bytes, and shell/format
// metacharacters. Targets always go through exec argv, never a shell, so this is defence in depth.
// hasUnsafeTargetChar 拒絕可能跳脫 node service 固定 argv 的目標：開頭的 "-"（避免被當成選項）、控制／
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

// Mtr runs `mtr` in report mode so it sends a fixed number of cycles, prints a per-hop report, and
// exits — the only non-interactive form usable over the API. `--no-dns` mirrors traceroute's `-n`
// (numeric output) and `--report-wide` keeps long IPv6 addresses from being truncated. `-6` is
// forced for IPv6 literal targets, matching Trace; a hostname is left for mtr to resolve itself.
// Validation and the fixed argv are identical to Trace, so mtr cannot reach a wider target space.
// Mtr 以 report 模式執行 `mtr`:送出固定次數的循環、印出每躍點報告後結束——這是經由 API 唯一可用的
// 非互動形式。`--no-dns` 對應 traceroute 的 `-n`(數字輸出),`--report-wide` 避免長 IPv6 位址被截斷。
// IPv6 字面目標強制 `-6`(與 Trace 一致);主機名則交由 mtr 自行解析。驗證與固定 argv 與 Trace 相同,
// 故 mtr 無法觸及更廣的目標範圍。
func (r Runner) Mtr(target string) Result {
	if err := ValidateHostTarget(target); err != nil {
		return Result{OK: false, Output: err.Error()}
	}
	args := []string{r.MtrPath, "--report", "--report-cycles", "4", "--no-dns", "--report-wide"}
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

func (r Runner) WireGuardStatus() Result {
	return r.run(r.WgPath, "show")
}

func (r Runner) BirdStatus() Result {
	status := r.run(r.BirdcPath, "show", "status")
	protocols := r.run(r.BirdcPath, "show", "protocols", "all")
	output := strings.TrimSpace(
		"birdc show status:\n" + status.Output + "\n\nbirdc show protocols all:\n" + protocols.Output,
	)
	return Result{OK: status.OK && protocols.OK, Output: output}
}

// PeerStatus returns the detailed BIRD protocol state for a single peer, used by the per-peer
// status views (the web admin/portal pages and the bot's /listpeers). protocolName is validated
// and passed as fixed argv, never a shell.
func (r Runner) PeerStatus(protocolName string) Result {
	protocolName = strings.TrimSpace(protocolName)
	if !safeNameRE.MatchString(protocolName) {
		return Result{OK: false, Output: "invalid protocol_name"}
	}
	return r.run(r.BirdcPath, "show", "protocols", "all", protocolName)
}

// PeerWireGuard returns a single peer's WireGuard tunnel status via `wg show <interface>`. wg-quick
// names the interface after the config file's basename, so the interface name equals the peer's
// protocol name (e.g. DN42_0090) — the same value used for the .conf files and the BIRD protocol.
// When the tunnel is not up, `wg show` exits non-zero with "No such device"; that output is still
// returned (OK=false) since it is useful status. protocolName is validated and passed as fixed argv.
// PeerWireGuard 以 `wg show <介面>` 回傳單一對等的 WireGuard 隧道狀態。wg-quick 以設定檔基本名命名介面,
// 故介面名等同對等的 protocol name(如 DN42_0090)——亦即 .conf 檔與 BIRD protocol 所用的同一值。隧道
// 未啟動時 `wg show` 以「No such device」非零結束,其輸出仍會回傳(OK=false),因為那是有用的狀態。
// protocolName 經驗證並以固定 argv 傳入。
func (r Runner) PeerWireGuard(protocolName string) Result {
	protocolName = strings.TrimSpace(protocolName)
	if !safeNameRE.MatchString(protocolName) {
		return Result{OK: false, Output: "invalid protocol_name"}
	}
	return r.run(r.WgPath, "show", protocolName)
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
	// The node service runs as root, but the BIRD daemon runs unprivileged (typically user `bird`); give the
	// BIRD peer dir and its snippet that group so `birdc configure` can read the include without
	// loosening the 0750/0640 mode. The WireGuard file is left root-only (it holds the private key).
	// node service 以 root 執行,但 BIRD 守護程序以非特權身分(通常是 `bird` 使用者)執行;將 BIRD 對等目錄與
	// 其片段設為該群組,使 `birdc configure` 能讀取 include 而不放寬 0750/0640 權限。WireGuard 檔案維持
	// 僅 root(其含私鑰)。
	if err := chownToGroup(r.BirdPeerDir, r.BirdPeerGroup); err != nil {
		return DeployResult{OK: false, Output: err.Error(), Files: files}
	}
	if err := chownToGroup(files[1], r.BirdPeerGroup); err != nil {
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
	if req.RequestID == "" {
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
			return "", errors.New("wireguard_private_key is required in the node service config for WireGuard deployment")
		}
		return strings.ReplaceAll(config, placeholder, r.WireGuardKey), nil
	}
	return config, nil
}

func validateDeployRequest(req DeployRequest) error {
	if req.RequestID == "" {
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

// ensureChildPath verifies child resolves strictly inside parent, guarding against path traversal
// before the node service writes a peer config. The relative path must not be "." (the dir itself) nor
// start with ".." (an escape), so e.g. a crafted protocol_name cannot redirect the write elsewhere.
// ensureChildPath 確認 child 解析後嚴格位於 parent 之內，於 node service 寫入對等設定前防止路徑穿越：
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

// chownToGroup sets only the group owner of path (the user owner is left unchanged) to group, so the
// unprivileged BIRD daemon — typically user `bird` — can read peer configs the root-run node service writes.
// The mode bits stay at their restrictive 0750/0640, so files never become world-readable; only the
// group is corrected from root to e.g. `bird`. An empty group disables this (operators who run BIRD
// as root, or manage the group via a setgid dir). WireGuard files are never passed here — they hold
// the private key and must stay root-only. A missing group is a hard error so a misconfigured
// bird_peer_group surfaces at deploy time rather than as a later silent "Permission denied".
// chownToGroup 僅將 path 的群組擁有者(保留使用者擁有者不變)設為 group,使以非特權身分(通常是
// `bird` 使用者)執行的 BIRD 守護程序能讀取由 root 執行的 node service 所寫入的對等設定。權限位維持嚴格的
// 0750/0640,檔案不會變成全域可讀;僅將群組由 root 修正為例如 `bird`。空字串則停用此行為(適用於以
// root 執行 BIRD,或以 setgid 目錄管理群組者)。WireGuard 檔案永不傳入此處——它們含私鑰,必須維持僅
// root 可存取。找不到群組視為硬性錯誤,使設定錯誤的 bird_peer_group 在部署時即浮現,而非日後默默的
// 「Permission denied」。
func chownToGroup(path string, group string) error {
	if group == "" {
		return nil
	}
	g, err := user.LookupGroup(group)
	if err != nil {
		return fmt.Errorf("bird_peer_group %q not found: %w", group, err)
	}
	gid, err := strconv.Atoi(g.Gid)
	if err != nil {
		return fmt.Errorf("bird_peer_group %q has invalid gid %q: %w", group, g.Gid, err)
	}
	if err := os.Chown(path, -1, gid); err != nil {
		return fmt.Errorf("set group %q on %s: %w", group, path, err)
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
