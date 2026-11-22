package web

import (
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/mhsanaei/3x-ui/v3/internal/amneziawgkern"
	"github.com/mhsanaei/3x-ui/v3/internal/amneziawgnet"
	"github.com/mhsanaei/3x-ui/v3/internal/bandwidthexchange"
	"github.com/mhsanaei/3x-ui/v3/internal/tuic"
)

const bandwidthExchangePath = "/bandwidth/v1/exchange"

func mountBandwidthExchange(group *gin.RouterGroup, handler http.Handler) {
	mountBandwidthEndpoint(group, bandwidthExchangePath, handler)
}

func mountBandwidthPolicy(group *gin.RouterGroup, handler http.Handler) {
	if handler == nil {
		return
	}
	mountBandwidthEndpoint(group, bandwidthexchange.PolicyPath, handler)
	group.POST(bandwidthexchange.PolicyPath+"/", func(c *gin.Context) {
		c.AbortWithStatus(http.StatusNotFound)
	})
}

func mountBandwidthEndpoint(group *gin.RouterGroup, path string, handler http.Handler) {
	if handler == nil {
		return
	}
	group.POST(path, func(c *gin.Context) {
		if c.Request.TLS == nil {
			c.AbortWithStatus(http.StatusNotFound)
			return
		}
		handler.ServeHTTP(c.Writer, c.Request)
	})
}

func (s *Server) loadBandwidthTLSCertificate() (*tls.Certificate, error) {
	certFile, err := s.settingService.GetCertFile()
	if err != nil {
		return nil, err
	}
	keyFile, err := s.settingService.GetKeyFile()
	if err != nil {
		return nil, err
	}
	return bandwidthTLSCertificate(certFile, keyFile, time.Now())
}

func bandwidthTLSCertificate(certFile, keyFile string, now time.Time) (*tls.Certificate, error) {
	if certFile == "" || keyFile == "" {
		return nil, errors.New("bandwidth node requires a direct HTTPS certificate and private key")
	}
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, fmt.Errorf("load bandwidth node HTTPS certificate: %w", err)
	}
	if cert.Leaf == nil || now.Before(cert.Leaf.NotBefore) || !now.Before(cert.Leaf.NotAfter) {
		return nil, errors.New("bandwidth node HTTPS certificate is outside its validity period")
	}
	return &cert, nil
}

func checkBandwidthSidecars(configured bool) error {
	kernel := amneziawgkern.GetManager()
	if (!configured && (tuic.GetManager().HasRunning() || amneziawgnet.GetManager().HasRunning() || kernel.HasRunning())) ||
		amneziawgnet.GetOutboundManager().HasRunning() {
		return errors.New("stop existing TUIC and AmneziaWG sidecars before enabling bandwidth management")
	}
	// A hot reload keeps this process's interfaces. A cold start admits only
	// an earlier managed interface whose persisted ownership and live
	// identity the manager can verify before rebuilding it.
	owned := make(map[string]bool)
	var recoverInterface func(string) (bool, error)
	if configured {
		for _, id := range kernel.ManagedIDs() {
			if current, ok := kernel.TrafficStateFor(id); ok {
				owned[current.Name] = true
			}
		}
	} else {
		recoverInterface = kernel.RecoverableBandwidthInterface
	}
	interfaces, err := net.Interfaces()
	if err != nil {
		return fmt.Errorf("inspect host interfaces before enabling bandwidth management: %w", err)
	}
	return checkBandwidthKernelInterfaces(interfaces, owned, recoverInterface)
}

func checkBandwidthKernelInterfaces(interfaces []net.Interface, owned map[string]bool, recoverInterface func(string) (bool, error)) error {
	for _, iface := range interfaces {
		if !strings.HasPrefix(iface.Name, "xui-awg") || owned[iface.Name] {
			continue
		}
		if recoverInterface != nil {
			recoverable, err := recoverInterface(iface.Name)
			if err != nil {
				return fmt.Errorf("verify recovery of kernel AmneziaWG interface %q: %w", iface.Name, err)
			}
			if recoverable {
				continue
			}
		}
		return fmt.Errorf("remove existing kernel AmneziaWG interface %q before enabling bandwidth management", iface.Name)
	}
	return nil
}
