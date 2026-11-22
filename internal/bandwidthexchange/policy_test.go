package bandwidthexchange

import (
	"encoding/json/v2"
	"slices"
	"strings"
	"testing"
)

func TestPolicyBindingsWireAndDigest(t *testing.T) {
	legacy := PolicyAccount{Email: "user", VLESSFingerprint: strings.Repeat("a", 64)}
	snapshot := PolicySnapshot{NodeID: "node-a", Generation: "generation-a", Accounts: []PolicyAccount{legacy}}
	const legacyDigest = "aa46d0739ae6553fc892ff252bdafed62a3aaad936d1c29f404c8bf9c1d43c78"
	if snapshot.Digest() != legacyDigest {
		t.Fatalf("legacy digest = %q, want %q", snapshot.Digest(), legacyDigest)
	}
	first := PolicyBinding{Protocol: "http", Fingerprint: CredentialFingerprint("http", CredentialParts("login", "first"))}
	second := PolicyBinding{Protocol: "http", Fingerprint: CredentialFingerprint("http", CredentialParts("login", "second"))}
	third := PolicyBinding{Protocol: "shadowsocks-2022", Fingerprint: CredentialFingerprint("shadowsocks-2022", "password")}
	snapshot.Accounts = append(snapshot.Accounts, PolicyAccount{Email: "other", Bindings: []PolicyBinding{third, first, second}})
	data, err := json.Marshal(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := ReadPolicySnapshot(strings.NewReader(string(data)))
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(decoded.Accounts[1].EffectiveBindings(), []PolicyBinding{third, first, second}) {
		t.Fatal("generic bindings changed on the wire")
	}
	slices.Reverse(decoded.Accounts[1].Bindings)
	slices.Reverse(decoded.Accounts)
	if decoded.Digest() != snapshot.Digest() || snapshot.Digest() == legacyDigest {
		t.Fatal("digest must include bindings independently of order")
	}
	if !slices.Equal(decoded.Accounts[0].Bindings, []PolicyBinding{second, first, third}) {
		t.Fatal("computing the digest mutated binding order")
	}
	decoded.Accounts[0].Bindings[0].Fingerprint = first.Fingerprint
	if decoded.Digest() == snapshot.Digest() {
		t.Fatal("a changed fingerprint did not change the digest")
	}
}

func TestPolicyRejectsInvalidBindings(t *testing.T) {
	pin := strings.Repeat("a", 64)
	binding := `{"protocol":"vless","fingerprint":"` + pin + `"}`
	tests := []struct {
		name   string
		fields string
	}{
		{"missing", ""},
		{"duplicate generic", `,"bindings":[` + binding + `,` + binding + `]`},
		{"duplicate legacy", `,"vless_fingerprint":"` + pin + `","bindings":[` + binding + `]`},
		{"unknown field", `,"bindings":[` + strings.Replace(binding, `{"protocol"`, `{"unexpected":true,"protocol"`, 1) + `]`},
		{"incorrect protocol case", `,"bindings":[` + strings.Replace(binding, "vless", "VLESS", 1) + `]`},
		{"invalid fingerprint", `,"bindings":[` + strings.Replace(binding, pin, strings.ToUpper(pin), 1) + `]`},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			wire := `{"node_id":"node-a","generation":"generation-a","accounts":[{"email":"user","client_id":"","requested_bits_per_second":0` + test.fields + `}]}`
			if _, err := ReadPolicySnapshot(strings.NewReader(wire)); err == nil {
				t.Fatal("invalid bindings accepted")
			}
		})
	}
}

func TestCredentialPartsPreserveExactBoundaries(t *testing.T) {
	if got := CredentialParts("é", "\x00", ""); got != "2:é1:\x000:" {
		t.Fatalf("credential parts encoding = %q", got)
	}
	if CredentialParts("left:right", "tail") == CredentialParts("left", "right:tail") {
		t.Fatal("different credential components produced the same encoding")
	}
}
