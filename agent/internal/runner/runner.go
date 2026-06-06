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

func ValidateTarget(target string) error {
	target = strings.TrimSpace(target)
	if target == "" || len(target) > 255 {
		return errors.New("invalid target length")
	}
	if strings.ContainsAny(target, ";&|`$<>\\\n\r\t") {
		return errors.New("target contains unsupported characters")
	}
	if ip := net.ParseIP(target); ip != nil {
		return nil
	}
	if _, _, err := net.ParseCIDR(target); err == nil {
		return nil
	}
	for _, label := range strings.Split(target, ".") {
		if label == "" || len(label) > 63 {
			return errors.New("invalid hostname")
		}
		for _, ch := range label {
			if (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') || (ch >= '0' && ch <= '9') || ch == '-' || ch == '_' {
				continue
			}
			return errors.New("invalid hostname character")
		}
	}
	return nil
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
	if err := ValidateTarget(target); err != nil {
		return Result{OK: false, Output: err.Error()}
	}
	return r.run(r.PingPath, "-c", "4", "-W", "3", target)
}

func (r Runner) MTR(target string) Result {
	if err := ValidateTarget(target); err != nil {
		return Result{OK: false, Output: err.Error()}
	}
	return r.run(r.MtrPath, "-r", "-c", "5", "-w", target)
}

func (r Runner) Route(target string) Result {
	if err := ValidateTarget(target); err != nil {
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
