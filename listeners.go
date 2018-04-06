// Ecca Authentication Proxy
//
// Handles Eccentric Authentication in a web proxy for browsers.
//
// Copyright 2015, Guido Witmond <guido@witmond.nl>
// Licensed under AGPL v3 or later. See LICENSE

// Motto: Long live the connections

package main // eccaproxy

import (
	"net"
	"log"
	"crypto/tls"
	"crypto/x509"
	"github.com/gwitmond/eccentric-authentication" // package eccentric
)

type caller struct {
     //Token  string  // long random id for the user interface to address them
     UserCN   string
     App      string
     Tlsconn *tls.Conn  // the actual tcp connection where the caller is waiting
}

// Global variable
var callers_waiting = make(map[string] caller)
var active_calls    = make(map[string] caller)

func addWaiter(tlsconn *tls.Conn, remoteCN, app string) {
     token := makeToken()
     log.Printf("Store %v call from %v under token %v\n", app, remoteCN, token)
     // TODO: assert token is not in callers_waiting already;
     callers_waiting[token] = caller {
         UserCN:  remoteCN,
	 App:     app,
	 Tlsconn: tlsconn,
     }
     log.Printf("callers_waiting is %v\n", callers_waiting)
}

// type ipListener struct {
// 	Endpoint string                  // ip:port
// 	ListenerCN string                // our CN (server name)
// 	ListenerTLSCertPEM []byte        // the cert we provide to the callers/clients
// 	ListenerTLSPrivKeyPEM []byte     // and the private key

// 	CallerCN string                   // the caller's CN we expect
// 	CallerCertPEM  []byte             // the caller's certificate  (superfluous)
// 	CallerFPCACertPEM []byte          // the FPCA that signs the callers' client certificates
// 	//Responder func(*tls.Conn)
// }


type listener struct {
	Application string               // chat/voice/video/ etc, as long as both endpoints agree
	OnionAddress string              // xyz.onion address
	Endpoint string                  // our local listening point (where the onion data gets delivered)
	ListenerCN string                // our CN (server name)
	ListenerTLSCertPEM []byte        // the cert we provide to the callers/clients
	ListenerTLSPrivKeyPEM []byte     // and the private key

	CallerCN string                  // the caller's CN we expect
	CallerCertPEM  []byte            // the caller's certificate  (superfluous)
	CallerFPCACertPEM []byte         // the FPCA that signs the callers' client certificates

	OnionPrivKey []byte              // the privkey of the ephemeral .onion address
}


/* createTorListener creates and starts a Tor Hidden Service
 * to let the given caller connect using the app.
 * Returns: the listener details to recreate it at a later run.
 */
func createTorListener(ourCreds *credentials, callerCert *x509.Certificate, app string) (listener) {
	// check to see if we get sane credentials
	_, err := tls.X509KeyPair(ourCreds.Cert, ourCreds.Priv)
	check(err)

	// Fetch the Signer of the invitee/caller
	callerCN := callerCert.Subject.CommonName
	callerFPCACert, err := findFPCACert(callerCN)
	check(err)
	log.Printf("CallerFPCACert is: %#v", callerFPCACert.Subject.CommonName)
	callerCertPEM := eccentric.PEMEncode(callerCert)
	callerFPCACertPEM := eccentric.PEMEncode(callerFPCACert)

	// Create listening socket for the onion hidden service and get its endpoint address
	netl, err := net.Listen("tcp", "127.0.0.1:0")
	check(err)
	endpoint := netl.Addr().String()

	// Create a .onion endpoint at port 443
	onionAddress, onionPrivKey := createTorHiddenService("443", endpoint)

	listener := listener {
		Application: app,
		Endpoint: endpoint,
		ListenerCN: ourCreds.CN,
		ListenerTLSCertPEM: ourCreds.Cert,
		ListenerTLSPrivKeyPEM: ourCreds.Priv,

		CallerCN: callerCN,
		CallerCertPEM: callerCertPEM,
		CallerFPCACertPEM: callerFPCACertPEM,

		OnionAddress: onionAddress,
		OnionPrivKey: []byte(onionPrivKey),
	}

	// start it
	go startListener(netl, listener)

	return listener
}


// func createListener(endpoint string, localEndpoint string, ourCreds *credentials, callerCert *x509.Certificate) (listener) {
// 	log.Printf("createListener at %v", endpoint)

// 	// check to see if we get sane credentials
// 	_, err := tls.X509KeyPair(ourCreds.Cert, ourCreds.Priv)
// 	check(err)

// 	callerCN := callerCert.Subject.CommonName
// 	callerFPCACert, err := findFPCACert(callerCN)
// 	check(err)
// 	log.Printf("CallerFPCACert is: %#v", callerFPCACert.Subject.CommonName)
// 	callerCertPEM := eccentric.PEMEncode(callerCert)
// 	callerFPCACertPEM := eccentric.PEMEncode(callerFPCACert)

// 	return listener {
// 		Endpoint: endpoint,
// 		ListenerCN: ourCreds.CN,
// 		ListenerTLSCertPEM: ourCreds.Cert,
// 		ListenerTLSPrivKeyPEM: ourCreds.Priv,

// 		CallerCN: callerCN,
// 		CallerCertPEM: callerCertPEM,
// 		CallerFPCACertPEM: callerFPCACertPEM,
// 	}
// }


func findFPCACert(cn string) (*x509.Certificate, error) {
	_, host, err := eccentric.ParseCN(cn)
	check(err)
	domain := getHostname(host)

	fpca, err := eccentric.FetchFPCA(domain)
	check(err)

	return fpca, err
}


// Start each of the listeners.
// To be called at startup
func restartAllTorListeners() {
	listeners, err := getAllListeners()
	check(err)

	for _, listener := range listeners {
		restartTorListener(listener)
	}
}


// func startListener(listener listener) {
// 	// The CA-pool specifies which client certificates can log in to our site.
// 	CallerFPCACert := eccentric.PEMDecode(listener.CallerFPCACertPEM)
// 	pool := x509.NewCertPool()
// 	pool.AddCert(&CallerFPCACert)

// 	listenerTLSCert, err := tls.X509KeyPair(listener.ListenerTLSCertPEM, listener.ListenerTLSPrivKeyPEM)
// 	check(err)

// 	listenerConfig :=  &tls.Config{
// 		ServerName: listener.ListenerCN,
// 		Certificates: []tls.Certificate{listenerTLSCert},
// 		ClientCAs: pool,
// 		ClientAuth: tls.RequireAndVerifyClientCert,
// 	}

// 	netl, err := net.Listen("tcp", listener.Endpoint)
// 	check(err)
// 	log.Printf("Started Listener at %v for %v", listener.Endpoint, listener.Endpoint)
// 	go AwaitIncomingConnection(netl, listenerConfig, listener.CallerCN)
// }

func restartTorListener(listener listener) {
	// This is what we want:
	// use a fresh port guaranteed to be available
	//netl, err := net.Listen("tcp", "127.0.0.1:0")

	// This is what we do:
	// Reopen the endpoint that was used to create the hidden service.
	// Tor assumes it's only used for services at well known ports that never change.
	// It appears that changing the local listening port to a fresh port at restart
	// of the proxy makes other tor nodes that have connected to us before break.
	// Those nodes fail to connect the first N attempts.
	netl, err := net.Listen("tcp", listener.Endpoint)
	check(err)
	endpoint := netl.Addr().String()

	// Restart a .onion endpoint at port 443
	err = restartTorHiddenService(listener.OnionPrivKey, listener.OnionAddress, "443", endpoint)
	check(err)
	//if onionAddress != listener.OnionAddress {
	//	log.Printf("Expected %v, got %v", listener.OnionAddress, onionAddress)
	//	panic("Restarted with different address than when we started.")
	//}
	log.Printf("Restarted Listener at %v for %v", endpoint, listener.OnionAddress)

	startListener(netl, listener)
}


func startListener(netl net.Listener, listener listener) {
	// The CA-pool specifies which client certificates can log in to our site.
	CallerFPCACert := eccentric.PEMDecode(listener.CallerFPCACertPEM)
	pool := x509.NewCertPool()
	pool.AddCert(&CallerFPCACert)

	listenerTLSCert, err := tls.X509KeyPair(listener.ListenerTLSCertPEM, listener.ListenerTLSPrivKeyPEM)
	check(err)

	listenerConfig :=  &tls.Config{
		ServerName: listener.ListenerCN,
		Certificates: []tls.Certificate{listenerTLSCert},
		ClientCAs: pool,
		ClientAuth: tls.RequireAndVerifyClientCert,
	}

	go AwaitIncomingConnection(netl, listenerConfig, listener.CallerCN, listener.Application)
}


// Await Incoming connection on the given net.Listener.
func AwaitIncomingConnection(listener net.Listener, serverConfig *tls.Config, userCN, app string) {
	log.Printf("Awaiting connections on %v", listener.Addr())

	for {
		conn, err := listener.Accept()
		check(err)
		go answerIncomingConnection(conn, serverConfig, userCN, app)
	}
}


// Answer the incoming connection, verify the identity of the remote party.
// Hang up if it is not the one we expect.
func answerIncomingConnection(conn net.Conn, serverConfig *tls.Config, userCN, app string) {
	log.Printf("Connection from: %v", conn.RemoteAddr())

	tlsconn := tls.Server(conn, serverConfig)
	err := tlsconn.Handshake()
	if err != nil {
		log.Printf("Listener could not perform TLS handshake: %v", err)
		return
	}

	connState := tlsconn.ConnectionState()
	log.Printf("Server.TLS.ConnectionState is: %#v", connState)
	peerCerts := connState.PeerCertificates
	for _, cert := range peerCerts {
		log.Printf("Peer cert subject: %s", cert.Subject.CommonName)
	}

	if len(peerCerts) == 0 {
		log.Printf("Rejecting connection without certificate")
		tlsconn.Write([]byte("No certificate. Go Away."))
		tlsconn.Close()
		return
	}

	if peerCerts[0].Subject.CommonName != userCN {
		log.Printf("Rejecting user %v is not %v.", peerCerts[0].Subject.CommonName, userCN)
		_, err := conn.Write([]byte("We don't expect you. Go Away."))
		check(err)
		tlsconn.Close()
		return
	}

	// Now we have established an authenticated connection to the EXPECTED party.
	// Hand the socket to the user app
	addWaiter(tlsconn, userCN, app)
	//TODO: signal Front-end
	return
}
