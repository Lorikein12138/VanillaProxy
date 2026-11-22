package bandwidthexchange

import (
	"bytes"
	"context"
	"encoding/json/v2"
	"errors"
	"fmt"
	"net/http"
	"net/url"

	"github.com/mhsanaei/3x-ui/v3/internal/bandwidthlease"
)

// Target binds a configured endpoint and its verified TLS identity to a
// canonical node ID, current generation and configured eligible client IDs.
// ClientIDs must remain immutable throughout the call.
type Target struct {
	URL           string
	NodeID        string
	Generation    string
	ClientIDs     map[string]struct{}
	Authorization string
}

// Validate checks the static endpoint and expected identity.
func (target Target) Validate() error {
	endpoint, err := url.Parse(target.URL)
	if err != nil || endpoint.Scheme != "https" || endpoint.Hostname() == "" || endpoint.User != nil ||
		endpoint.Opaque != "" || endpoint.RawQuery != "" || endpoint.ForceQuery || endpoint.Fragment != "" {
		return errors.New("bandwidth exchange requires a configured HTTPS endpoint")
	}
	if !ValidIdentity(target.NodeID) || !ValidIdentity(target.Generation) {
		return errors.New("invalid bandwidth exchange target")
	}
	return nil
}

// Exchange offers earlier grants and returns verified demands for use by the
// root authority. A successful response can omit stale grants silently.
// The supplied transport must bind the HTTPS host to the configured node with
// normal certificate and hostname checks. Any custom RoundTripper must enforce
// those checks before sending credentials or grants and honor cancellation.
func Exchange(ctx context.Context, client *http.Client, target Target, grants []bandwidthlease.Grant) ([]Demand, error) {
	demands, _, err := ExchangeWithApplied(ctx, client, target, grants)
	return demands, err
}

// ExchangeWithApplied also returns the exact grants the verified node reports
// applying. Both demands and receipts are withheld if response validation fails.
func ExchangeWithApplied(ctx context.Context, client *http.Client, target Target, grants []bandwidthlease.Grant) ([]Demand, []bandwidthlease.Grant, error) {
	if err := target.Validate(); err != nil {
		return nil, nil, err
	}
	if client == nil || len(grants) > MaxClients {
		return nil, nil, errors.New("invalid bandwidth exchange client or grants")
	}
	transport := client.Transport
	if transport == nil {
		transport = http.DefaultTransport
	}
	if standard, ok := transport.(*http.Transport); ok {
		if standard == nil || (standard.TLSClientConfig != nil && standard.TLSClientConfig.InsecureSkipVerify) ||
			standard.DialTLS != nil || standard.DialTLSContext != nil {
			return nil, nil, errors.New("bandwidth exchange requires transport TLS verification")
		}
	}

	incoming := request{
		NodeID: target.NodeID, Generation: target.Generation, Grants: make([]wireEntry, 0, len(grants)),
	}
	sent := make(map[bandwidthlease.Grant]struct{}, len(grants))
	for _, grant := range grants {
		_, eligible := target.ClientIDs[grant.Challenge.ClientID]
		if grant.Challenge.NodeID != target.NodeID || !eligible {
			return nil, nil, errors.New("grant is outside the configured bandwidth exchange target")
		}
		sent[grant] = struct{}{}
		incoming.Grants = append(incoming.Grants, toWire(grant.Challenge, grant.BitsPerSecond))
	}
	if !validEntries(incoming.Grants) {
		return nil, nil, errors.New("invalid bandwidth exchange grants")
	}
	data, err := json.Marshal(incoming)
	if err != nil {
		return nil, nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, target.URL, bytes.NewReader(data))
	if err != nil {
		return nil, nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	if target.Authorization != "" {
		req.Header.Set("Authorization", target.Authorization)
	}

	exchangeClient := &http.Client{
		Transport: transport,
		Timeout:   client.Timeout,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	reply, err := exchangeClient.Do(req)
	if err != nil {
		return nil, nil, fmt.Errorf("bandwidth exchange with configured node failed: %w", err)
	}
	defer reply.Body.Close()
	if reply.TLS == nil || len(reply.TLS.VerifiedChains) == 0 {
		return nil, nil, errors.New("bandwidth exchange response lacks verified TLS identity")
	}
	if reply.StatusCode != http.StatusOK {
		return nil, nil, fmt.Errorf("bandwidth exchange returned HTTP %d", reply.StatusCode)
	}
	var outgoing response
	if err := readJSON(reply.Body, &outgoing); err != nil {
		return nil, nil, fmt.Errorf("invalid bandwidth exchange response: %w", err)
	}
	if outgoing.NodeID != target.NodeID || outgoing.Generation != target.Generation || !validEntries(outgoing.Demands) {
		return nil, nil, errors.New("bandwidth exchange response differs from the configured target")
	}
	if !validEntries(outgoing.Applied) {
		return nil, nil, errors.New("bandwidth exchange response contains invalid applied grants")
	}
	demands := make([]Demand, 0, len(outgoing.Demands))
	var incarnationID string
	for _, entry := range outgoing.Demands {
		if _, eligible := target.ClientIDs[entry.ClientID]; !eligible {
			return nil, nil, errors.New("demand is outside the configured bandwidth exchange target")
		}
		if incarnationID != "" && incarnationID != entry.IncarnationID {
			return nil, nil, errors.New("bandwidth exchange response contains multiple node incarnations")
		}
		incarnationID = entry.IncarnationID
		demands = append(demands, Demand{entry.challenge(target.NodeID), *entry.BitsPerSecond})
	}
	applied := make([]bandwidthlease.Grant, 0, len(outgoing.Applied))
	for _, entry := range outgoing.Applied {
		grant := entry.grant(target.NodeID)
		if _, ok := sent[grant]; !ok {
			return nil, nil, errors.New("applied grant does not match a sent bandwidth exchange grant")
		}
		if incarnationID != "" && incarnationID != entry.IncarnationID {
			return nil, nil, errors.New("bandwidth exchange response contains multiple node incarnations")
		}
		incarnationID = entry.IncarnationID
		applied = append(applied, grant)
	}
	return demands, applied, nil
}
