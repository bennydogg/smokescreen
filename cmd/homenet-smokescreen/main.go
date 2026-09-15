// homenet-smokescreen: Stripe's Smokescreen with a LAN-shaped role lookup
// and time-boxed grants. Lives in the bennydogg/smokescreen fork as its own
// command; policy, compose and deploy tooling live in the homenet repo under
// network/services/smokescreen/.
//
// Upstream Smokescreen identifies the calling service by client TLS
// certificate. On this LAN every proxy client is a VM with a DHCP
// reservation, so the role is looked up from the client IP instead
// (conf/roles.yaml). Unknown clients get UnknownRole, which the ACL handles
// as its own service (report mode by default — the old squid "unclassified"
// bucket, now visible instead of silent).
//
// Durable policy lives in conf/acl.yaml (git). Temporary grants live in
// conf/grants.yaml on the host (operational state, written by
// tools/egress-grant, never in git): each grant is role + host glob + expiry
// and is consulted at decision time, so a grant takes effect within a few
// seconds of being written and expires on its own — no restart, no drift in
// the versioned ACL.
//
// Subcommands (anything else is passed straight to Smokescreen's CLI):
//
//	smokescreen check                       validate acl + roles + grants, exit 0/1
//	smokescreen decide <role> <host>        print the decision the ACL would make
package main

import (
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/stripe/smokescreen/cmd"
	"github.com/stripe/smokescreen/pkg/smokescreen"
	acl "github.com/stripe/smokescreen/pkg/smokescreen/acl/v1"
	"gopkg.in/yaml.v2"
)

const (
	defaultRolesFile  = "/etc/smokescreen/roles.yaml"
	defaultGrantsFile = "/etc/smokescreen/grants.yaml"
	defaultACLFile    = "/etc/smokescreen/acl.yaml"
	defaultUnknown    = "unclassified"
	grantsPollEvery   = 5 * time.Second
)

// ---------------------------------------------------------------- roles ---

type rolesFile struct {
	Roles []struct {
		Name    string   `yaml:"name"`
		Members []string `yaml:"members"`
	} `yaml:"roles"`
	UnknownRole string `yaml:"unknown_role"`
}

type roleEntry struct {
	name string
	net  *net.IPNet
}

type roleTable struct {
	entries []roleEntry
	unknown string
}

func loadRoles(path string) (*roleTable, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var rf rolesFile
	if err := yaml.UnmarshalStrict(raw, &rf); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	t := &roleTable{unknown: rf.UnknownRole}
	if t.unknown == "" {
		t.unknown = defaultUnknown
	}
	seen := map[string]bool{}
	for _, r := range rf.Roles {
		if r.Name == "" {
			return nil, fmt.Errorf("%s: role with empty name", path)
		}
		if seen[r.Name] {
			return nil, fmt.Errorf("%s: role %q listed twice", path, r.Name)
		}
		seen[r.Name] = true
		for _, m := range r.Members {
			m = strings.TrimSpace(m)
			if !strings.Contains(m, "/") {
				if strings.Contains(m, ":") {
					m += "/128"
				} else {
					m += "/32"
				}
			}
			_, n, err := net.ParseCIDR(m)
			if err != nil {
				return nil, fmt.Errorf("%s: role %q member %q: %w", path, r.Name, m, err)
			}
			t.entries = append(t.entries, roleEntry{name: r.Name, net: n})
		}
	}
	return t, nil
}

func (t *roleTable) lookup(ip net.IP) string {
	for _, e := range t.entries {
		if e.net.Contains(ip) {
			return e.name
		}
	}
	return t.unknown
}

// roleFromRequest never fails: an unknown client is a role too, and the ACL
// decides what that role may do. Failing here would make Smokescreen log
// "role cannot be determined" and deny, which hides the client from the
// report/harvest workflow.
func (t *roleTable) roleFromRequest(req *http.Request) (string, error) {
	host, _, err := net.SplitHostPort(req.RemoteAddr)
	if err != nil {
		host = req.RemoteAddr
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return t.unknown, nil
	}
	return t.lookup(ip), nil
}

// --------------------------------------------------------------- grants ---

type grant struct {
	Role    string `yaml:"role"`
	Host    string `yaml:"host"`
	Expires string `yaml:"expires"`
	Reason  string `yaml:"reason"`
	By      string `yaml:"by"`
	expires time.Time
}

type grantsFile struct {
	Grants []grant `yaml:"grants"`
}

func parseGrants(raw []byte, path string) ([]grant, error) {
	var gf grantsFile
	if err := yaml.UnmarshalStrict(raw, &gf); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	out := make([]grant, 0, len(gf.Grants))
	for i, g := range gf.Grants {
		if g.Role == "" || g.Host == "" || g.Expires == "" {
			return nil, fmt.Errorf("%s: grant %d needs role, host and expires", path, i)
		}
		if err := validateGlob(g.Host); err != nil {
			return nil, fmt.Errorf("%s: grant %d: %w", path, i, err)
		}
		t, err := time.Parse(time.RFC3339, g.Expires)
		if err != nil {
			return nil, fmt.Errorf("%s: grant %d expires %q: want RFC3339", path, i, g.Expires)
		}
		g.expires = t
		out = append(out, g)
	}
	return out, nil
}

// Same rules as Smokescreen's ACL globs: exact host, or "*.suffix".
func validateGlob(g string) error {
	if g == "" || g == "*" || g == "*." {
		return fmt.Errorf("glob %q must not match everything", g)
	}
	if strings.HasPrefix(g, "*") && !strings.HasPrefix(g, "*.") {
		return fmt.Errorf("glob %q: wildcard must be a full leading label (*.example.com)", g)
	}
	if strings.Contains(strings.TrimPrefix(g, "*"), "*") {
		return fmt.Errorf("glob %q: only a leading wildcard is supported", g)
	}
	if strings.HasPrefix(g, ".") {
		return fmt.Errorf("glob %q: squid-style leading dot is not a Smokescreen glob (use example.com plus *.example.com)", g)
	}
	return nil
}

func hostMatchesGlob(host, glob string) bool {
	h := strings.TrimRight(strings.ToLower(host), ".")
	g := strings.TrimRight(strings.ToLower(glob), ".")
	if strings.HasPrefix(g, "*.") {
		return strings.HasSuffix(h, g[1:])
	}
	return h == g
}

// grantsDecider wraps the loaded ACL: an unexpired grant for (role, host)
// allows, everything else is the ACL's call. The file is re-read when its
// mtime changes (checked at most every grantsPollEvery); a malformed file
// keeps the last good set and logs an error.
type grantsDecider struct {
	base acl.Decider
	path string
	log  *logrus.Logger

	mu        sync.Mutex
	checkedAt time.Time
	mtime     time.Time
	grants    []grant
}

func newGrantsDecider(base acl.Decider, path string, log *logrus.Logger) *grantsDecider {
	d := &grantsDecider{base: base, path: path, log: log}
	d.reload(true)
	return d
}

func (d *grantsDecider) reload(force bool) {
	d.mu.Lock()
	defer d.mu.Unlock()
	now := time.Now()
	if !force && now.Sub(d.checkedAt) < grantsPollEvery {
		return
	}
	d.checkedAt = now
	st, err := os.Stat(d.path)
	if err != nil {
		if !os.IsNotExist(err) {
			d.log.WithError(err).Error("grants: stat failed; keeping last set")
		} else if len(d.grants) != 0 {
			d.grants = nil
			d.log.Info("grants: file removed; no temporary grants active")
		}
		return
	}
	if !force && st.ModTime().Equal(d.mtime) {
		return
	}
	raw, err := os.ReadFile(d.path)
	if err != nil {
		d.log.WithError(err).Error("grants: read failed; keeping last set")
		return
	}
	gs, err := parseGrants(raw, d.path)
	if err != nil {
		d.log.WithError(err).Error("grants: parse failed; keeping last set")
		return
	}
	d.grants = gs
	d.mtime = st.ModTime()
	d.log.WithField("count", len(gs)).Info("grants: loaded")
}

func (d *grantsDecider) Decide(args acl.DecideArgs) (acl.Decision, error) {
	service, host := args.Service, args.Host
	d.reload(false)
	d.mu.Lock()
	grants := d.grants
	d.mu.Unlock()
	now := time.Now()
	for _, g := range grants {
		if now.After(g.expires) {
			continue
		}
		if (g.Role == service || g.Role == "*") && hostMatchesGlob(host, g.Host) {
			return acl.Decision{
				Result:  acl.Allow,
				Reason:  fmt.Sprintf("temporary grant until %s (%s)", g.expires.UTC().Format(time.RFC3339), g.Reason),
				Project: "grant",
			}, nil
		}
	}
	return d.base.Decide(args)
}

// ------------------------------------------------------------------ main ---

func env(name, def string) string {
	if v := os.Getenv(name); v != "" {
		return v
	}
	return def
}

func loadACL(logger *logrus.Logger, path string) (*acl.ACL, error) {
	return acl.New(logger, acl.NewYAMLLoader(path), nil)
}

func runCheck(logger *logrus.Logger) int {
	aclPath := env("SMOKESCREEN_ACL_FILE", defaultACLFile)
	rolesPath := env("SMOKESCREEN_ROLES_FILE", defaultRolesFile)
	grantsPath := env("SMOKESCREEN_GRANTS_FILE", defaultGrantsFile)
	ok := true

	a, err := loadACL(logger, aclPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "FAIL acl   %s: %v\n", aclPath, err)
		ok = false
	} else {
		fmt.Printf("ok   acl   %s: %d services", aclPath, len(a.Rules))
		if a.DefaultRule != nil {
			fmt.Printf(", default rule present")
		} else {
			fmt.Printf(", NO default rule (unknown roles are denied)")
		}
		fmt.Println()
	}

	roles, err := loadRoles(rolesPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "FAIL roles %s: %v\n", rolesPath, err)
		ok = false
	} else {
		fmt.Printf("ok   roles %s: %d members, unknown -> %q\n", rolesPath, len(roles.entries), roles.unknown)
		if a != nil {
			for _, e := range roles.entries {
				if _, present := a.Rules[e.name]; !present {
					fmt.Fprintf(os.Stderr, "FAIL roles: role %q (%s) has no service in the ACL; it would fall to the default rule\n", e.name, e.net)
					ok = false
				}
			}
			if _, present := a.Rules[roles.unknown]; !present && a.DefaultRule == nil {
				fmt.Fprintf(os.Stderr, "FAIL roles: unknown role %q has no ACL service and there is no default rule\n", roles.unknown)
				ok = false
			}
		}
	}

	if raw, err := os.ReadFile(grantsPath); err == nil {
		gs, err := parseGrants(raw, grantsPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "FAIL grants %v\n", err)
			ok = false
		} else {
			active := 0
			for _, g := range gs {
				if time.Now().Before(g.expires) {
					active++
				}
			}
			fmt.Printf("ok   grants %s: %d listed, %d active\n", grantsPath, len(gs), active)
		}
	} else if os.IsNotExist(err) {
		fmt.Printf("ok   grants %s: absent (no temporary grants)\n", grantsPath)
	} else {
		fmt.Fprintf(os.Stderr, "FAIL grants %s: %v\n", grantsPath, err)
		ok = false
	}

	if !ok {
		return 1
	}
	return 0
}

func runDecide(logger *logrus.Logger, role, host string) int {
	a, err := loadACL(logger, env("SMOKESCREEN_ACL_FILE", defaultACLFile))
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	var dec acl.Decider = a
	if _, err := os.Stat(env("SMOKESCREEN_GRANTS_FILE", defaultGrantsFile)); err == nil {
		dec = newGrantsDecider(a, env("SMOKESCREEN_GRANTS_FILE", defaultGrantsFile), logger)
	}
	d, err := dec.Decide(acl.DecideArgs{Service: role, Host: host})
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	verdict := map[acl.DecisionResult]string{
		acl.Allow: "ALLOW", acl.AllowAndReport: "ALLOW (report: enforce would deny)", acl.Deny: "DENY",
	}[d.Result]
	fmt.Printf("%s  role=%s host=%s reason=%q project=%s default_rule=%t\n", verdict, role, host, d.Reason, d.Project, d.Default)
	if d.Result == acl.Deny {
		return 2
	}
	return 0
}

func main() {
	logger := logrus.New()
	logger.Formatter = &logrus.JSONFormatter{}
	logger.Out = os.Stdout

	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "check":
			logger.Out = os.Stderr
			os.Exit(runCheck(logger))
		case "decide":
			if len(os.Args) != 4 {
				fmt.Fprintln(os.Stderr, "usage: smokescreen decide <role> <host>")
				os.Exit(2)
			}
			logger.Out = os.Stderr
			os.Exit(runDecide(logger, os.Args[2], os.Args[3]))
		}
	}

	roles, err := loadRoles(env("SMOKESCREEN_ROLES_FILE", defaultRolesFile))
	if err != nil {
		logger.Fatalf("roles: %v", err)
	}

	conf, err := cmd.NewConfiguration(os.Args, logger)
	if err != nil {
		logger.Fatalf("configuration: %v", err)
	}
	if conf == nil {
		return // --help / --version handled by Smokescreen
	}
	if conf.EgressACL == nil {
		logger.Fatal("refusing to start without --egress-acl-file: this proxy is allowlist-or-deny by design")
	}

	conf.RoleFromRequest = roles.roleFromRequest
	conf.Healthcheck = http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		_, _ = w.Write([]byte("ok\n"))
	})
	conf.EgressACL = newGrantsDecider(conf.EgressACL, env("SMOKESCREEN_GRANTS_FILE", defaultGrantsFile), logger)

	adapter := &smokescreen.Log2LogrusWriter{Entry: conf.Log.WithField("stdlog", "1")}
	log.SetOutput(adapter)
	log.SetFlags(0)

	logger.WithFields(logrus.Fields{
		"roles":        len(roles.entries),
		"unknown_role": roles.unknown,
		"listen":       fmt.Sprintf("%s:%d", conf.Ip, conf.Port),
	}).Info("homenet smokescreen starting")
	smokescreen.StartWithConfig(conf, nil)
}
