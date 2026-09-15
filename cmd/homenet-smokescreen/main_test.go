package main

import (
	"net"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/sirupsen/logrus"
	acl "github.com/stripe/smokescreen/pkg/smokescreen/acl/v1"
)

func writeTemp(t *testing.T, name, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestLoadRolesAndLookup(t *testing.T) {
	p := writeTemp(t, "roles.yaml", `
roles:
  - name: brain
    members: [192.168.10.68, 192.168.0.68]
  - name: dev
    members: [192.168.5.0/24]
  - name: v6
    members: ["fd00::1"]
  - name: empty
    members: []
unknown_role: nobody
`)
	rt, err := loadRoles(p)
	if err != nil {
		t.Fatal(err)
	}
	cases := map[string]string{
		"192.168.10.68": "brain", "192.168.0.68": "brain", "192.168.5.111": "dev",
		"fd00::1": "v6", "10.9.9.9": "nobody",
	}
	for ip, want := range cases {
		if got := rt.lookup(net.ParseIP(ip)); got != want {
			t.Errorf("%s: got %q want %q", ip, got, want)
		}
	}
	req := &http.Request{RemoteAddr: "192.168.5.7:40000"}
	if role, err := rt.roleFromRequest(req); err != nil || role != "dev" {
		t.Errorf("roleFromRequest: %q %v", role, err)
	}
	req = &http.Request{RemoteAddr: "garbage"}
	if role, err := rt.roleFromRequest(req); err != nil || role != "nobody" {
		t.Errorf("roleFromRequest garbage: %q %v", role, err)
	}
}

func TestLoadRolesRejectsBadInput(t *testing.T) {
	bad := []string{
		"roles:\n  - name: a\n    members: [notanip]\n",
		"roles:\n  - name: a\n    members: [1.2.3.4]\n  - name: a\n    members: [1.2.3.5]\n",
		"roles:\n  - members: [1.2.3.4]\n",
		"roles: []\nbogus_key: 1\n",
	}
	for i, body := range bad {
		if _, err := loadRoles(writeTemp(t, "r.yaml", body)); err == nil {
			t.Errorf("case %d: expected error", i)
		}
	}
}

func TestValidateGlobAndMatch(t *testing.T) {
	for _, g := range []string{"", "*", "*.", "*foo.com", "a.*.b", ".example.com"} {
		if err := validateGlob(g); err == nil {
			t.Errorf("validateGlob(%q): expected error", g)
		}
	}
	for _, g := range []string{"example.com", "*.example.com", "a-b.c"} {
		if err := validateGlob(g); err != nil {
			t.Errorf("validateGlob(%q): %v", g, err)
		}
	}
	match := []struct {
		host, glob string
		want       bool
	}{
		{"example.com", "example.com", true},
		{"EXAMPLE.com.", "example.com", true},
		{"sub.example.com", "example.com", false},
		{"sub.example.com", "*.example.com", true},
		{"example.com", "*.example.com", false},
		{"notexample.com", "*.example.com", false},
		{"", "example.com", false},
	}
	for _, m := range match {
		if got := hostMatchesGlob(m.host, m.glob); got != m.want {
			t.Errorf("hostMatchesGlob(%q,%q)=%v want %v", m.host, m.glob, got, m.want)
		}
	}
}

func TestParseGrants(t *testing.T) {
	gs, err := parseGrants([]byte(`grants:
  - {role: a, host: x.test, expires: "2030-01-01T00:00:00Z", reason: r, by: b}
  - {role: "*", host: "*.y.test", expires: "2000-01-01T00:00:00Z"}
`), "g")
	if err != nil {
		t.Fatal(err)
	}
	if len(gs) != 2 || gs[0].expires.Year() != 2030 {
		t.Fatalf("unexpected grants: %+v", gs)
	}
	bad := []string{
		"grants:\n  - {role: a, host: x.test}\n",                                         // no expiry
		"grants:\n  - {role: a, host: x.test, expires: tomorrow}\n",                      // bad time
		"grants:\n  - {role: a, host: \".x.test\", expires: \"2030-01-01T00:00:00Z\"}\n", // squid dot
		"grants: [ {role: a", // malformed
		"grantz: []\n",       // unknown key
	}
	for i, b := range bad {
		if _, err := parseGrants([]byte(b), "g"); err == nil {
			t.Errorf("case %d: expected error", i)
		}
	}
}

type fakeDecider struct{ calls int }

func (f *fakeDecider) Decide(args acl.DecideArgs) (acl.Decision, error) {
	f.calls++
	return acl.Decision{Result: acl.Deny, Reason: "base"}, nil
}

func TestGrantsDeciderPrecedenceAndReload(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "grants.yaml")
	base := &fakeDecider{}
	log := logrus.New()
	log.Out = os.Stderr

	// absent file: everything goes to the base decider
	d := newGrantsDecider(base, path, log)
	if dec, _ := d.Decide(acl.DecideArgs{Service: "a", Host: "x.test"}); dec.Result != acl.Deny || base.calls != 1 {
		t.Fatalf("absent grants: %+v calls=%d", dec, base.calls)
	}

	future := time.Now().Add(time.Hour).UTC().Format(time.RFC3339)
	past := time.Now().Add(-time.Hour).UTC().Format(time.RFC3339)
	body := "grants:\n" +
		"  - {role: a, host: x.test, expires: \"" + future + "\", reason: ok}\n" +
		"  - {role: a, host: old.test, expires: \"" + past + "\"}\n" +
		"  - {role: \"*\", host: \"*.any.test\", expires: \"" + future + "\"}\n"
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	d.reload(true)

	cases := []struct {
		svc, host string
		want      acl.DecisionResult
	}{
		{"a", "x.test", acl.Allow},          // live grant
		{"b", "x.test", acl.Deny},           // other role
		{"a", "old.test", acl.Deny},         // expired
		{"zzz", "deep.any.test", acl.Allow}, // wildcard role + glob
		{"a", "any.test", acl.Deny},         // apex not covered by *.any.test
	}
	for _, c := range cases {
		dec, err := d.Decide(acl.DecideArgs{Service: c.svc, Host: c.host})
		if err != nil || dec.Result != c.want {
			t.Errorf("%s/%s: got %v (%q) err=%v want %v", c.svc, c.host, dec.Result, dec.Reason, err, c.want)
		}
	}

	// malformed rewrite keeps the last good set
	if err := os.WriteFile(path, []byte("grants: [ {role"), 0o644); err != nil {
		t.Fatal(err)
	}
	d.reload(true)
	if dec, _ := d.Decide(acl.DecideArgs{Service: "a", Host: "x.test"}); dec.Result != acl.Allow {
		t.Errorf("malformed file should keep last good grants, got %v", dec.Result)
	}

	// removal drops them
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	d.reload(true)
	if dec, _ := d.Decide(acl.DecideArgs{Service: "a", Host: "x.test"}); dec.Result != acl.Deny {
		t.Errorf("removed file should drop grants, got %v", dec.Result)
	}
}
