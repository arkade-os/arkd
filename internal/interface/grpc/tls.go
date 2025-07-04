package grpcservice

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"
)

func generateOperatorTLSKeyCert(datadir string, extraIPs, extraDomains []string) error {
	if err := makeDirectoryIfNotExists(datadir); err != nil {
		return err
	}
	keyPath := filepath.Join(datadir, tlsKeyFile)
	certPath := filepath.Join(datadir, tlsCertFile)

	// if key and cert files already exist nothing to do here.
	if pathExists(keyPath) && pathExists(certPath) {
		return nil
	}

	organization := "ark"
	now := time.Now()
	validUntil := now.AddDate(1, 0, 0)

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)

	// Generate a serial number that's below the serialNumberLimit.
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return fmt.Errorf("failed to generate serial number: %s", err)
	}

	// Collect the host's IP addresses, including loopback, in a slice.
	ipAddresses := []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")}

	if len(extraIPs) > 0 {
		for _, ip := range extraIPs {
			ipAddresses = append(ipAddresses, net.ParseIP(ip))
		}
	}

	// addIP appends an IP address only if it isn't already in the slice.
	addIP := func(ipAddr net.IP) {
		for _, ip := range ipAddresses {
			if net.IP.Equal(ip, ipAddr) {
				return
			}
		}
		ipAddresses = append(ipAddresses, ipAddr)
	}

	// Add all the interface IPs that aren't already in the slice.
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return err
	}
	for _, a := range addrs {
		ipAddr, _, err := net.ParseCIDR(a.String())
		if err == nil {
			addIP(ipAddr)
		}
	}

	host, err := os.Hostname()
	if err != nil {
		return err
	}

	dnsNames := []string{host}
	if host != "localhost" {
		dnsNames = append(dnsNames, "localhost")
	}

	if len(extraDomains) > 0 {
		dnsNames = append(dnsNames, extraDomains...)
	}

	dnsNames = append(dnsNames, "unix", "unixpacket")

	priv, err := createOrLoadTLSKey(keyPath)
	if err != nil {
		return err
	}

	keybytes, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		return err
	}

	// construct certificate template
	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{organization},
			CommonName:   host,
		},
		NotBefore: now.Add(-time.Hour * 24),
		NotAfter:  validUntil,

		KeyUsage: x509.KeyUsageKeyEncipherment |
			x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,

		DNSNames:    dnsNames,
		IPAddresses: ipAddresses,
	}

	derBytes, err := x509.CreateCertificate(
		rand.Reader, &template, &template, &priv.PublicKey, priv,
	)
	if err != nil {
		return fmt.Errorf("failed to create certificate: %v", err)
	}

	certBuf := &bytes.Buffer{}
	if err := pem.Encode(
		certBuf, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes},
	); err != nil {
		return fmt.Errorf("failed to encode certificate: %v", err)
	}

	keyBuf := &bytes.Buffer{}
	if err := pem.Encode(
		keyBuf, &pem.Block{Type: "EC PRIVATE KEY", Bytes: keybytes},
	); err != nil {
		return fmt.Errorf("failed to encode private key: %v", err)
	}

	if err := os.WriteFile(certPath, certBuf.Bytes(), 0644); err != nil {
		return err
	}
	if err := os.WriteFile(keyPath, keyBuf.Bytes(), 0600); err != nil {
		// nolint:all
		os.Remove(certPath)
		return err
	}

	return nil
}

func createOrLoadTLSKey(keyPath string) (*ecdsa.PrivateKey, error) {
	if !pathExists(keyPath) {
		return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	}

	b, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, err
	}

	key, err := privateKeyFromPEM(b)
	if err != nil {
		return nil, err
	}
	return key.(*ecdsa.PrivateKey), nil
}

func privateKeyFromPEM(pemBlock []byte) (crypto.PrivateKey, error) {
	var derBlock *pem.Block
	for {
		derBlock, pemBlock = pem.Decode(pemBlock)
		if derBlock == nil {
			return nil, fmt.Errorf("tls: failed to find any PEM data in key input")
		}
		if derBlock.Type == "PRIVATE KEY" || strings.HasSuffix(derBlock.Type, " PRIVATE KEY") {
			break
		}
	}
	return parsePrivateKey(derBlock.Bytes)
}

func parsePrivateKey(der []byte) (crypto.PrivateKey, error) {
	if key, err := x509.ParsePKCS1PrivateKey(der); err == nil {
		return key, nil
	}
	if key, err := x509.ParsePKCS8PrivateKey(der); err == nil {
		switch key := key.(type) {
		case *rsa.PrivateKey, *ecdsa.PrivateKey, ed25519.PrivateKey:
			return key, nil
		default:
			return nil, fmt.Errorf("tls: found unknown private key type in PKCS#8 wrapping")
		}
	}
	if key, err := x509.ParseECPrivateKey(der); err == nil {
		return key, nil
	}

	return nil, fmt.Errorf("tls: failed to parse private key")
}
