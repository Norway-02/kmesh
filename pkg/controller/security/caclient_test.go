/*
 * Copyright The Kmesh Authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package security

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"os"
	"path"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/agiledragon/gomonkey/v2"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	pb "istio.io/api/security/v1alpha1"
	istiogrpc "istio.io/istio/pilot/pkg/grpc"
	testutil "istio.io/istio/pilot/test/util"
	"istio.io/istio/pkg/config/constants"
	"istio.io/istio/pkg/security"
	"istio.io/istio/pkg/spiffe"
	"istio.io/istio/security/pkg/credentialfetcher/plugin"

	"kmesh.net/kmesh/pkg/nets"
)

const (
	mockServerAddress = "localhost:0"
)

var (
	fakeCert = []string{"kmesh", "bar"}
)

type mockIstioServer struct {
	pb.UnimplementedIstioCertificateServiceServer
	Certs         []string
	Authenticator *security.FakeAuthenticator
	Err           error
}

func (ca *mockIstioServer) CreateCertificate(ctx context.Context, in *pb.IstioCertificateRequest) (*pb.IstioCertificateResponse, error) {
	if ca.Err == nil {
		return &pb.IstioCertificateResponse{CertChain: ca.Certs}, nil
	}
	return nil, ca.Err
}

// tlsOption Create a gRPC server option that configures the server's TLS
// The following function is adapted from istio tlsOption
// (https://github.com/istio/istio/blob/1.20.0/security/pkg/nodeagent/caclient/providers/citadel/client_test.go)
func tlsOption(t *testing.T) grpc.ServerOption {
	t.Helper()
	cert, err := tls.LoadX509KeyPair(
		filepath.Join("./testdata/cert-chain.pem"),
		filepath.Join("./testdata/key.pem"))
	if err != nil {
		t.Fatal(err)
	}
	peerCertVerifier := spiffe.NewPeerCertVerifier()
	if err := peerCertVerifier.AddMappingFromPEM("cluster.local",
		testutil.ReadFile(t, filepath.Join("./testdata/root-cert.pem"))); err != nil {
		t.Fatal(err)
	}
	return grpc.Creds(credentials.NewTLS(&tls.Config{
		Certificates: []tls.Certificate{cert},
		ClientAuth:   tls.VerifyClientCertIfGiven,
		ClientCAs:    peerCertVerifier.GetGeneralCertPool(),
		MinVersion:   tls.VersionTLS12,
	}))
}

// serve Create and start a local gRPC server
// The following function is adapted from istio serve
// (https://github.com/istio/istio/blob/1.20.0/security/pkg/nodeagent/caclient/providers/citadel/client_test.go)
func serve(t *testing.T, ca mockIstioServer, opts ...grpc.ServerOption) string {
	// create a local grpc server
	s := grpc.NewServer(opts...)
	t.Cleanup(s.Stop)
	listen, err := net.Listen("tcp", mockServerAddress)
	if err != nil {
		t.Fatalf("failed to listen: %v", err)
	}

	go func() {
		pb.RegisterIstioCertificateServiceServer(s, &ca)
		if err := s.Serve(listen); err != nil {
			t.Logf("failed to serve: %v", err)
		}
	}()
	_, port, _ := net.SplitHostPort(listen.Addr().String())
	return fmt.Sprintf("localhost:%s", port)
}

// GrpcConnect creates a client connection to the given addr
func GrpcConnect(addr string, RootCert string) (*grpc.ClientConn, error) {
	var (
		err        error
		conn       *grpc.ClientConn
		tlsOptions *istiogrpc.TLSOptions
	)

	if RootCert == "" {
		tlsOptions = nil
	} else {
		tlsOptions = &istiogrpc.TLSOptions{
			RootCert:      RootCert,
			ServerAddress: addr,
		}
	}

	opts, err := istiogrpc.ClientOptions(nil, tlsOptions)
	if err != nil {
		return nil, err
	}

	if conn, err = grpc.Dial(addr, opts...); err != nil {
		return nil, err
	}

	return conn, nil
}

func TestClient(t *testing.T) {
	checkSign := func(t *testing.T, cli CaClient, expectError bool) {
		t.Helper()
		identity := "spiffe:///ns/default/sa/default"
		resp, err := cli.CsrSend([]byte{0o1}, 1, identity)
		if expectError != (err != nil) {
			t.Fatalf("expected error:%v, got error:%v", expectError, err)
		}
		if !expectError && !reflect.DeepEqual(resp, fakeCert) {
			t.Fatalf("expected cert: %v", resp)
		}
	}

	certDir := filepath.Join("./testdata")
	t.Run("cert always present", func(t *testing.T) {
		server := mockIstioServer{Certs: fakeCert, Err: nil, Authenticator: security.NewFakeAuthenticator("ca")}
		address := serve(t, server, tlsOption(t))
		opts := &security.Options{
			CredFetcher: plugin.CreateTokenPlugin("testdata/token"),
			ProvCert:    certDir,
		}
		rootCert := path.Join(certDir, constants.RootCertFilename)
		key := path.Join(certDir, constants.KeyFilename)
		cert := path.Join(certDir, constants.CertChainFilename)
		tlsOpts := &tlsOptions{
			RootCert: rootCert,
			Key:      key,
			Cert:     cert,
		}

		patches := gomonkey.NewPatches()
		patches.ApplyFunc(nets.GrpcConnect, func(addr string) (*grpc.ClientConn, error) {
			return GrpcConnect(address, rootCert)
		})
		defer patches.Reset()

		cli, err := newCaClient(opts, tlsOpts)
		if err != nil {
			t.Errorf("failed to create ca client: %v", err)
		}
		t.Cleanup(func() {
			_ = cli.Close()
		})

		server.Authenticator.Set("fake", "")
		checkSign(t, cli, false)
		// Expiring the token is harder, so just switch to only allow certs
		server.Authenticator.Set("", "istiod.istio-system.svc")
		checkSign(t, cli, false)
	})

	t.Run("GrpcConnect error", func(t *testing.T) {
		patches := gomonkey.NewPatches()
		patches.ApplyFunc(nets.GrpcConnect, func(addr string) (*grpc.ClientConn, error) {
			return nil, errors.New("connection failed")
		})
		defer patches.Reset()

		cli, err := newCaClient(nil, nil)
		if err == nil {
			t.Fatal("expected error from newCaClient, got nil")
		}
		if !strings.Contains(err.Error(), "failed to create grpcconnect") {
			t.Errorf("unexpected error message: %v", err)
		}
		if cli != nil {
			t.Errorf("expected nil client, got %v", cli)
		}
	})
}

func TestCaClient(t *testing.T) {
	testCases := map[string]struct {
		server       mockIstioServer
		expectedCert []string
		expectedErr  string
	}{
		"Valid certs": {
			server:       mockIstioServer{Certs: fakeCert, Err: nil},
			expectedCert: fakeCert,
			expectedErr:  "",
		},
		"Empty response": {
			server:       mockIstioServer{Certs: []string{}, Err: nil},
			expectedCert: nil,
			expectedErr:  "invalid empty CertChain",
		},
		"Single cert response": {
			server:       mockIstioServer{Certs: []string{"kmesh"}, Err: nil},
			expectedCert: nil,
			expectedErr:  "invalid empty CertChain",
		},
		"Server error": {
			server:       mockIstioServer{Err: errors.New("rpc error: ca service unavailable")},
			expectedCert: nil,
			expectedErr:  "create certificate failed",
		},
	}

	for id, tc := range testCases {
		t.Run(id, func(t *testing.T) {
			address := serve(t, tc.server)

			patches := gomonkey.NewPatches()
			patches.ApplyFunc(nets.GrpcConnect, func(addr string) (*grpc.ClientConn, error) {
				return GrpcConnect(address, "")
			})
			defer patches.Reset()

			cli, err := newCaClient(nil, nil)
			if err != nil {
				t.Errorf("failed to create ca client: %v", err)
			}
			t.Cleanup(func() {
				_ = cli.Close()
			})

			identity := "spiffe:///ns/default/sa/default"
			resp, err := cli.CsrSend([]byte{0o1}, 1, identity)
			if err != nil {
				if !strings.Contains(err.Error(), tc.expectedErr) {
					t.Errorf("error (%s) does not match expected error (%s)", err.Error(), tc.expectedErr)
				}
			} else {
				if tc.expectedErr != "" {
					t.Errorf("expect error: %s but got no error", tc.expectedErr)
				} else if !reflect.DeepEqual(resp, tc.expectedCert) {
					t.Errorf("resp: got %+v, expected %v", resp, tc.expectedCert)
				}
			}
		})
	}
}

func TestStandardCerts(t *testing.T) {
	testCases := []struct {
		name     string
		input    []string
		expected string
	}{
		{
			name:     "empty slice",
			input:    []string{},
			expected: "",
		},
		{
			name:     "nil slice",
			input:    nil,
			expected: "",
		},
		{
			name:     "single cert with newline",
			input:    []string{"CERT1\n"},
			expected: "CERT1\n",
		},
		{
			name:     "single cert without newline",
			input:    []string{"CERT1"},
			expected: "CERT1",
		},
		{
			name:     "multiple certs without trailing newlines",
			input:    []string{"CERT1", "CERT2", "CERT3"},
			expected: "CERT1\nCERT2\nCERT3",
		},
		{
			name:     "multiple certs with trailing newlines",
			input:    []string{"CERT1\n", "CERT2\n", "CERT3\n"},
			expected: "CERT1\nCERT2\nCERT3\n",
		},
		{
			name:     "mixed certs with and without trailing newlines",
			input:    []string{"CERT1\n", "CERT2", "CERT3\n"},
			expected: "CERT1\nCERT2\nCERT3\n",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			res := standardCerts(tc.input)
			if string(res) != tc.expected {
				t.Errorf("standardCerts(%v) = %q, want %q", tc.input, string(res), tc.expected)
			}
		})
	}
}

func TestFetchCert(t *testing.T) {
	certChainBytes, err := os.ReadFile(filepath.Join("testdata", "cert-chain.pem"))
	if err != nil {
		t.Fatal(err)
	}
	rootCertBytes, err := os.ReadFile(filepath.Join("testdata", "root-cert.pem"))
	if err != nil {
		t.Fatal(err)
	}

	identity := "spiffe://cluster.local/ns/default/sa/default"

	t.Run("successful fetch cert", func(t *testing.T) {
		validCerts := []string{string(certChainBytes), string(rootCertBytes)}
		server := mockIstioServer{Certs: validCerts, Err: nil}
		address := serve(t, server)

		patches := gomonkey.NewPatches()
		patches.ApplyFunc(nets.GrpcConnect, func(addr string) (*grpc.ClientConn, error) {
			return GrpcConnect(address, "")
		})
		defer patches.Reset()

		opts := NewSecurityOptions()
		cli, err := newCaClient(opts, nil)
		if err != nil {
			t.Fatalf("failed to create ca client: %v", err)
		}
		t.Cleanup(func() {
			_ = cli.Close()
		})

		secretItem, err := cli.FetchCert(identity)
		if err != nil {
			t.Fatalf("FetchCert failed: %v", err)
		}
		if secretItem == nil {
			t.Fatal("expected non-nil secretItem")
		}
		if secretItem.ResourceName != identity {
			t.Errorf("expected ResourceName %s, got %s", identity, secretItem.ResourceName)
		}
		if len(secretItem.CertificateChain) == 0 {
			t.Error("expected non-empty CertificateChain")
		}
		if len(secretItem.PrivateKey) == 0 {
			t.Error("expected non-empty PrivateKey")
		}
		if string(secretItem.RootCert) != string(rootCertBytes) {
			t.Errorf("expected RootCert %s, got %s", string(rootCertBytes), string(secretItem.RootCert))
		}
		if secretItem.ExpireTime.IsZero() {
			t.Error("expected non-zero ExpireTime")
		}
	})

	t.Run("server error on CsrSend", func(t *testing.T) {
		server := mockIstioServer{Err: errors.New("ca service unavailable")}
		address := serve(t, server)

		patches := gomonkey.NewPatches()
		patches.ApplyFunc(nets.GrpcConnect, func(addr string) (*grpc.ClientConn, error) {
			return GrpcConnect(address, "")
		})
		defer patches.Reset()

		opts := NewSecurityOptions()
		cli, err := newCaClient(opts, nil)
		if err != nil {
			t.Fatalf("failed to create ca client: %v", err)
		}
		t.Cleanup(func() {
			_ = cli.Close()
		})

		secretItem, err := cli.FetchCert(identity)
		if err == nil {
			t.Fatal("expected error, got nil")
		}
		if !strings.Contains(err.Error(), "create certificate failed") {
			t.Errorf("unexpected error: %v", err)
		}
		if secretItem != nil {
			t.Errorf("expected nil secretItem, got %v", secretItem)
		}
	})

	t.Run("parse cert error from invalid PEM", func(t *testing.T) {
		server := mockIstioServer{Certs: []string{"invalid-pem-cert-1", "invalid-pem-cert-2"}, Err: nil}
		address := serve(t, server)

		patches := gomonkey.NewPatches()
		patches.ApplyFunc(nets.GrpcConnect, func(addr string) (*grpc.ClientConn, error) {
			return GrpcConnect(address, "")
		})
		defer patches.Reset()

		opts := NewSecurityOptions()
		cli, err := newCaClient(opts, nil)
		if err != nil {
			t.Fatalf("failed to create ca client: %v", err)
		}
		t.Cleanup(func() {
			_ = cli.Close()
		})

		secretItem, err := cli.FetchCert(identity)
		if err == nil {
			t.Fatal("expected error parsing invalid cert PEM, got nil")
		}
		if !strings.Contains(err.Error(), "failed to extract expire time") {
			t.Errorf("unexpected error message: %v", err)
		}
		if secretItem != nil {
			t.Errorf("expected nil secretItem, got %v", secretItem)
		}
	})

	t.Run("generate CSR error from invalid options", func(t *testing.T) {
		opts := &security.Options{
			WorkloadRSAKeySize: -1,
		}
		patches := gomonkey.NewPatches()
		patches.ApplyFunc(nets.GrpcConnect, func(addr string) (*grpc.ClientConn, error) {
			return &grpc.ClientConn{}, nil
		})
		defer patches.Reset()

		cli, err := newCaClient(opts, nil)
		if err != nil {
			t.Fatalf("failed to create ca client: %v", err)
		}

		secretItem, err := cli.FetchCert(identity)
		if err == nil {
			t.Fatal("expected GenCSR error, got nil")
		}
		if secretItem != nil {
			t.Errorf("expected nil secretItem, got %v", secretItem)
		}
	})
}
