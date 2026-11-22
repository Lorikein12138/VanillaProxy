// Package xraybandwidthchild runs the metered core in an isolated subprocess.
package xraybandwidthchild

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	json "encoding/json/v2"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/mhsanaei/3x-ui/v3/internal/bandwidthipc"
	"github.com/mhsanaei/3x-ui/v3/internal/xraybandwidthchild/launch"
	"github.com/mhsanaei/3x-ui/v3/internal/xraybandwidthcore"
	"github.com/xtls/xray-core/common/platform"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/infra/conf/serial"
	_ "github.com/xtls/xray-core/main/distro/all"
)

// Command is the private child entry point of the panel binary.
const Command = launch.Command

const handshakeTimeout = 10 * time.Second

// Handshake is the private startup message shared with the parent.
type Handshake = launch.Handshake

// Run takes ownership of the private stdin pipe and serves until ctx is
// canceled. The sole argument is the path to the generated Xray JSON config.
func Run(ctx context.Context, args []string, stdin io.ReadCloser) (err error) {
	if len(args) != 1 || args[0] == "" || args[0] == "-" {
		_ = stdin.Close()
		return errors.New("metered Xray requires one configuration file path")
	}

	handshake, readErr := receiveHandshake(ctx, stdin)
	_ = stdin.Close()
	if readErr != nil {
		return readErr
	}
	permits, err := bandwidthipc.Dial(handshake.IPC)
	if err != nil {
		return err
	}
	var instance *core.Instance
	defer func() {
		_ = permits.Close()
		if instance != nil {
			if closeErr := instance.Close(); closeErr != nil {
				err = errors.Join(err, fmt.Errorf("close metered Xray: %w", closeErr))
			}
		}
	}()

	config, err := loadConfig(args[0], handshake.ConfigSHA256)
	if err != nil {
		return err
	}
	bindings, guarded, err := bindClients(config, handshake.Clients, handshake.Generated)
	if err != nil {
		return err
	}
	if err := validateInboundCoverage(config, bindings); err != nil {
		return err
	}
	if err := bindSidecarRelays(config, bindings, handshake.Relays); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	instance, err = xraybandwidthcore.NewWithManagedInbounds(ctx, config, bindings.resolve, permits.Acquire, guarded)
	if err != nil {
		return fmt.Errorf("construct metered Xray: %w", err)
	}
	if err := bindings.verifyMASQUEPacketGates(ctx, instance); err != nil {
		return err
	}
	if err := bindings.verifyWireGuardPacketGates(ctx, instance); err != nil {
		return err
	}
	if err := instance.Start(); err != nil {
		return fmt.Errorf("start metered Xray: %w", err)
	}
	if handshake.Ready != nil {
		if err := handshake.Ready.Notify(ctx); err != nil {
			return err
		}
	}
	<-ctx.Done()
	return nil
}

func receiveHandshake(ctx context.Context, stdin io.Reader) (Handshake, error) {
	// Require EOF before accepting the document. A missing message or writer
	// that never closes its pipe must not hold up shutdown or startup.
	ctx, cancel := context.WithTimeout(ctx, handshakeTimeout)
	defer cancel()
	type result struct {
		handshake Handshake
		err       error
	}
	done := make(chan result, 1)
	go func() {
		handshake, err := readHandshake(stdin)
		done <- result{handshake, err}
	}()
	select {
	case <-ctx.Done():
		return Handshake{}, fmt.Errorf("wait for metered Xray handshake: %w", ctx.Err())
	case result := <-done:
		return result.handshake, result.err
	}
}

func readHandshake(stdin io.Reader) (Handshake, error) {
	data, err := io.ReadAll(io.LimitReader(stdin, launch.MaxHandshakeSize+1))
	if err != nil || len(data) > launch.MaxHandshakeSize {
		return Handshake{}, errors.New("cannot read metered Xray handshake within size limit")
	}
	var handshake Handshake
	// Reject unknown members, duplicate names, invalid UTF-8 and trailing
	// data. Decoder errors can echo private values, so keep them out of logs.
	if err := json.Unmarshal(data, &handshake, json.RejectUnknownMembers(true)); err != nil {
		return Handshake{}, errors.New("invalid metered Xray handshake")
	}
	if handshake.IPC.Address == "" || handshake.IPC.Token == "" || len(handshake.Clients)+len(handshake.Relays) == 0 {
		return Handshake{}, errors.New("metered Xray handshake requires an IPC capability and managed inbounds")
	}
	if handshake.Ready != nil && !handshake.Ready.Valid() {
		return Handshake{}, errors.New("invalid metered Xray readiness destination")
	}
	if (handshake.Ready != nil || len(handshake.ConfigSHA256) != 0) && len(handshake.ConfigSHA256) != sha256.Size {
		return Handshake{}, errors.New("invalid metered Xray configuration fingerprint")
	}
	return handshake, nil
}

func loadConfig(path string, fingerprint []byte) (*core.Config, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open generated Xray configuration: %w", err)
	}
	defer file.Close()
	// The stock Xray executable resides alongside the generated config and
	// its data files. Keep that lookup when running inside the panel image.
	assetEnv := platform.NewEnvFlag(platform.AssetLocation)
	_, assetSet := os.LookupEnv(assetEnv.Name)
	_, assetAltSet := os.LookupEnv(assetEnv.AltName)
	if !assetSet && !assetAltSet {
		base, err := filepath.Abs(filepath.Dir(path))
		if err != nil {
			return nil, fmt.Errorf("resolve Xray asset directory: %w", err)
		}
		if err := os.Setenv(assetEnv.AltName, base); err != nil {
			return nil, fmt.Errorf("configure Xray asset directory: %w", err)
		}
	}
	var reader io.Reader = file
	if fingerprint != nil {
		data, err := io.ReadAll(file)
		if err != nil {
			return nil, fmt.Errorf("read generated Xray configuration: %w", err)
		}
		digest := sha256.Sum256(data)
		if subtle.ConstantTimeCompare(digest[:], fingerprint) != 1 {
			return nil, errors.New("generated Xray configuration changed before startup")
		}
		reader = bytes.NewReader(data)
	}
	config, err := serial.LoadJSONConfig(reader)
	if err != nil {
		return nil, fmt.Errorf("load generated Xray configuration: %w", err)
	}
	return config, nil
}
