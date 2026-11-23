// Command gencert generates a self-signed TLS certificate for the p2p
// signaling server, making it easy to enable --tls-cert/--tls-key.
package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"flag"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"time"
)

func main() {
	outDir := flag.String("out", ".", "output directory for server.crt and server.key")
	host := flag.String("host", "localhost", "hostname/IP to include in the certificate SAN")
	days := flag.Int("days", 365, "certificate validity in days")
	flag.Parse()

	if *days <= 0 {
		fmt.Fprintln(os.Stderr, "error: --days must be positive")
		os.Exit(2)
	}

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		fmt.Fprintln(os.Stderr, "generate key:", err)
		os.Exit(1)
	}

	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		fmt.Fprintln(os.Stderr, "serial:", err)
		os.Exit(1)
	}

	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: *host},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Duration(*days) * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{"localhost"},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}
	if ip := net.ParseIP(*host); ip != nil {
		tmpl.IPAddresses = append(tmpl.IPAddresses, ip)
	} else {
		tmpl.DNSNames = append(tmpl.DNSNames, *host)
	}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		fmt.Fprintln(os.Stderr, "create certificate:", err)
		os.Exit(1)
	}

	certPath := filepath.Join(*outDir, "server.crt")
	keyPath := filepath.Join(*outDir, "server.key")

	certOut, err := os.Create(certPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "create cert file:", err)
		os.Exit(1)
	}
	defer certOut.Close()
	if err := pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: der}); err != nil {
		fmt.Fprintln(os.Stderr, "write cert:", err)
		os.Exit(1)
	}

	keyBytes, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		fmt.Fprintln(os.Stderr, "marshal key:", err)
		os.Exit(1)
	}
	keyOut, err := os.Create(keyPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "create key file:", err)
		os.Exit(1)
	}
	defer keyOut.Close()
	if err := pem.Encode(keyOut, &pem.Block{Type: "EC PRIVATE KEY", Bytes: keyBytes}); err != nil {
		fmt.Fprintln(os.Stderr, "write key:", err)
		os.Exit(1)
	}

	fmt.Printf("wrote %s and %s\n", certPath, keyPath)
	fmt.Printf("server: p2p server --tls-cert %s --tls-key %s\n", certPath, keyPath)
	fmt.Printf("client: p2p client ... --tls --tls-insecure\n")
}
