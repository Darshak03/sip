package sip

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"math/big"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestTLSALPNProtocols(t *testing.T) {
	t.Run("nil returns default sip", func(t *testing.T) {
		protos := tlsALPNProtocols(nil)
		require.Equal(t, []string{"sip"}, protos)
	})

	t.Run("empty slice disables ALPN", func(t *testing.T) {
		empty := []string{}
		protos := tlsALPNProtocols(empty)
		require.Empty(t, protos)
	})

	t.Run("custom protocols", func(t *testing.T) {
		custom := []string{"h2", "http/1.1"}
		protos := tlsALPNProtocols(custom)
		require.Equal(t, []string{"h2", "http/1.1"}, protos)
	})

	t.Run("single custom protocol", func(t *testing.T) {
		custom := []string{"sip"}
		protos := tlsALPNProtocols(custom)
		require.Equal(t, []string{"sip"}, protos)
	})
}

func TestDialTLSConfig(t *testing.T) {
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	caTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	require.NoError(t, err)
	ca, err := x509.ParseCertificate(caDER)
	require.NoError(t, err)

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		DNSNames:     []string{"sip.example.com"},
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca, &key.PublicKey, caKey)
	require.NoError(t, err)
	srvConf := &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}}

	trusted := x509.NewCertPool()
	trusted.AddCert(ca)

	handshake := func(serverName string, roots *x509.CertPool) error {
		cli, srv := net.Pipe()
		defer cli.Close()
		defer srv.Close()
		go func() { _ = tls.Server(srv, srvConf).Handshake() }()
		conf := dialTLSConfig()
		conf.RootCAs = roots
		conf.ServerName = serverName
		return tls.Client(cli, conf).Handshake()
	}

	require.NoError(t, handshake("127.0.0.1", trusted), "a peer addressed by IP is checked on its chain only")
	require.NoError(t, handshake("sip.example.com", trusted))
	require.Error(t, handshake("other.example.com", trusted), "a peer addressed by name must match it")
	require.Error(t, handshake("127.0.0.1", x509.NewCertPool()), "the chain must verify")
}
