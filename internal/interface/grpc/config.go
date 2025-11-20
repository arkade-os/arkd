package grpcservice

import (
	"crypto/rand"
	"crypto/tls"
	"fmt"
	"net"
	"path/filepath"

	"golang.org/x/net/http2"
)

type Config struct {
	Datadir           string
	Port              uint32
	AdminPort         uint32
	NoTLS             bool
	NoMacaroons       bool
	TLSExtraIPs       []string
	TLSExtraDomains   []string
	HeartbeatInterval int64
	EnablePprof       bool
}

func (c Config) Validate() error {
	lis, err := net.Listen("tcp", c.address())
	if err != nil {
		return fmt.Errorf("invalid port: %s", err)
	}
	// nolint:all
	defer lis.Close()

	// Validate admin port if it's different from main port
	if c.hasAdminPort() {
		adminLis, err := net.Listen("tcp", c.adminAddress())
		if err != nil {
			return fmt.Errorf("invalid admin port: %s", err)
		}
		// nolint:all
		defer adminLis.Close()
	}

	if !c.NoTLS {
		tlsDir := c.tlsDatadir()
		tlsKeyExists := pathExists(filepath.Join(tlsDir, tlsKeyFile))
		tlsCertExists := pathExists(filepath.Join(tlsDir, tlsCertFile))
		if !tlsKeyExists && tlsCertExists {
			return fmt.Errorf(
				"found %s file but %s is missing. Please delete %s to make the "+
					"daemon recreating both files in path %s",
				tlsCertFile, tlsKeyFile, tlsCertFile, tlsDir,
			)
		}

		if len(c.TLSExtraIPs) > 0 {
			for _, ip := range c.TLSExtraIPs {
				if net.ParseIP(ip) == nil {
					return fmt.Errorf("invalid operator extra ip %s", ip)
				}
			}
		}
	}

	return nil
}

func (c Config) insecure() bool {
	return c.NoTLS
}

func (c Config) address() string {
	return fmt.Sprintf(":%d", c.Port)
}

func (c Config) gatewayAddress() string {
	return fmt.Sprintf("127.0.0.1:%d", c.Port)
}

func (c Config) adminAddress() string {
	return fmt.Sprintf(":%d", c.AdminPort)
}

func (c Config) adminGatewayAddress() string {
	return fmt.Sprintf("127.0.0.1:%d", c.AdminPort)
}

func (c Config) hasAdminPort() bool {
	return c.AdminPort != c.Port
}

func (c Config) macaroonsDatadir() string {
	return filepath.Join(c.Datadir, macaroonsFolder)
}

func (c Config) tlsDatadir() string {
	return filepath.Join(c.Datadir, tlsFolder)
}

func (c Config) tlsKey() string {
	if c.NoTLS {
		return ""
	}
	return filepath.Join(c.tlsDatadir(), tlsKeyFile)
}

func (c Config) tlsCert() string {
	if c.NoTLS {
		return ""
	}
	return filepath.Join(c.tlsDatadir(), tlsCertFile)
}

func (c Config) tlsConfig() (*tls.Config, error) {
	if c.NoTLS {
		return nil, nil
	}

	if c.tlsKey() == "" || c.tlsCert() == "" {
		return nil, fmt.Errorf("tls_key and tls_cert both needs to be provided")
	}

	certificate, err := tls.LoadX509KeyPair(c.tlsCert(), c.tlsKey())
	if err != nil {
		return nil, err
	}

	config := &tls.Config{
		MinVersion: tls.VersionTLS12,
		NextProtos: []string{
			"http/1.1", http2.NextProtoTLS, "h2-14",
		}, // h2-14 is just for compatibility. will be eventually removed.
		Certificates: []tls.Certificate{certificate},
		CipherSuites: []uint16{
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
		},
	}
	config.Rand = rand.Reader

	return config, nil
}
