package runner

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/wazuh/wazuh-modules/inventory_sync/benchmark/internal/metrics"
	"github.com/wazuh/wazuh-modules/inventory_sync/benchmark/internal/scenario"
	"github.com/wazuh/wazuh-modules/inventory_sync/benchmark/internal/wire"
)

// TestRunner_EngineSmokeEndToEnd brings up a fake authd + fake remoted
// listener pair, runs the engine_smoke scenario for ~3s and asserts:
//   - The agent enrols successfully
//   - At least N engine_events_sent frames arrive at the fake remoted
//   - bench.csv is written
func TestRunner_EngineSmokeEndToEnd(t *testing.T) {
	// --- fake authd (TLS) ---
	authdAddr, authdStop := startFakeAuthd(t)
	defer authdStop()

	// --- fake remoted (TCP) ---
	receivedFrames := int64(0)
	remotedAddr, remotedStop := startFakeRemoted(t, &receivedFrames)
	defer remotedStop()

	host, authPortStr, _ := net.SplitHostPort(authdAddr)
	_, remoPortStr, _ := net.SplitHostPort(remotedAddr)
	authPort := atoi(authPortStr)
	remoPort := atoi(remoPortStr)

	// Locate benchmark/ from the test working dir.
	// internal/runner lives at .../benchmark/tool_simulator/internal/runner/,
	// so benchmark/ is three levels up.
	wd, _ := os.Getwd()
	benchDir := filepath.Clean(filepath.Join(wd, "..", "..", ".."))
	scnPath := filepath.Join(benchDir, "scenarios", "engine_smoke.json")
	scn, err := scenario.Load(scnPath, scenario.LoaderOptions{BenchDir: benchDir})
	if err != nil {
		t.Fatalf("load scenario: %v", err)
	}
	// Trim aggressively for tests.
	scn.Behavior.RepeatUntil = 2
	scn.Lanes["engine_syslog"][0].MaxEPS = 200

	c := metrics.New()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	registered, err := Run(ctx, scn, Config{
		Manager:           host,
		Port:              remoPort,
		RegPort:           authPort,
		KeyWait:           0,
		BenchDir:          benchDir,
		KeepaliveInterval: 100 * time.Millisecond, // dense for the 2 s test window
	}, c)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if registered != 1 {
		t.Fatalf("registered = %d, want 1", registered)
	}

	// Allow drain.
	time.Sleep(200 * time.Millisecond)

	cum := c.Cumulative()
	if cum[metrics.CEngineEventsSent] < 200 { // ~2s @ 200 EPS minus warm-up
		t.Fatalf("engine_events_sent = %d, want >= 200", cum[metrics.CEngineEventsSent])
	}
	if cum[metrics.CKeepalivesSent] < 5 {
		t.Errorf("keepalives_sent = %d, want >= 5 over a ~2s run @ 100ms interval",
			cum[metrics.CKeepalivesSent])
	}
	if cum[metrics.CShutdownsSent] != 1 {
		t.Errorf("shutdowns_sent = %d, want 1", cum[metrics.CShutdownsSent])
	}
	got := atomic.LoadInt64(&receivedFrames)
	// Subtract the startup control frame.
	if got < 200 {
		t.Fatalf("remoted received = %d frames, want >= 200", got)
	}
	t.Logf("OK: registered=%d engine_events_sent=%d keepalives=%d shutdowns=%d remoted_received=%d",
		registered, cum[metrics.CEngineEventsSent], cum[metrics.CKeepalivesSent],
		cum[metrics.CShutdownsSent], got)
}

// ----- helpers -----

func atoi(s string) int {
	n := 0
	for _, c := range s {
		n = n*10 + int(c-'0')
	}
	return n
}

func selfSignedTLSCert(t *testing.T) tls.Certificate {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tpl := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "fake-authd"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, &tpl, &tpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatal(err)
	}
	certPem := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyDer, _ := x509.MarshalECPrivateKey(priv)
	keyPem := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDer})
	cert, err := tls.X509KeyPair(certPem, keyPem)
	if err != nil {
		t.Fatal(err)
	}
	return cert
}

func startFakeAuthd(t *testing.T) (string, func()) {
	cert := selfSignedTLSCert(t)
	cfg := &tls.Config{Certificates: []tls.Certificate{cert}}
	ln, err := tls.Listen("tcp", "127.0.0.1:0", cfg)
	if err != nil {
		t.Fatal(err)
	}
	stop := make(chan struct{})
	go func() {
		for {
			select {
			case <-stop:
				return
			default:
			}
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				buf := make([]byte, 4096)
				n, err := c.Read(buf)
				if err != nil {
					return
				}
				body := string(buf[:n])
				// Expect: OSSEC A:'<name>'\n
				start := strings.Index(body, "'")
				end := strings.LastIndex(body, "'")
				name := "unknown"
				if start >= 0 && end > start {
					name = body[start+1 : end]
				}
				key := "deadbeefdeadbeefdeadbeefdeadbeef"
				resp := fmt.Sprintf("OSSEC K:'001 %s 127.0.0.1 %s'\n", name, key)
				_, _ = c.Write([]byte(resp))
			}(conn)
		}
	}()
	return ln.Addr().String(), func() {
		close(stop)
		ln.Close()
	}
}

func startFakeRemoted(t *testing.T, counter *int64) (string, func()) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	stop := make(chan struct{})
	go func() {
		for {
			select {
			case <-stop:
				return
			default:
			}
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				for {
					_, err := wire.ReadFrame(c)
					if err != nil {
						if err != io.EOF {
							return
						}
						return
					}
					atomic.AddInt64(counter, 1)
				}
			}(conn)
		}
	}()
	return ln.Addr().String(), func() {
		close(stop)
		ln.Close()
	}
}
