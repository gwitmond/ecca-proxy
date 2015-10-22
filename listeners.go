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


type listener struct {
	Endpoint string                  // ip:port or abc.domain.tld or xyz.onion address
	ListenerCN string                // our CN (server name)
	ListenerTLSCertPEM []byte        // the cert we provide to the callers/clients
	ListenerTLSPrivKeyPEM []byte     // and the private key

	CallerCN string                   // the caller's CN we expect
	CallerCertPEM  []byte             // the caller's certificate  (superfluous)
	CallerFPCACertPEM []byte          // the FPCA that signs the callers' client certificates
	//Responder func(*tls.Conn)
}


func createListener(endpoint string, ourCreds *credentials, callerCert *x509.Certificate) (listener) {
	log.Printf("createListener at %v", endpoint)

	// check to see if we get sane credentials
	_, err := tls.X509KeyPair(ourCreds.Cert, ourCreds.Priv)
	check(err)

	callerCN := callerCert.Subject.CommonName
	callerFPCACert, err := findFPCACert(callerCN)
	check(err)
	log.Printf("CallerFPCACert is: %#v", callerFPCACert.Subject.CommonName)
	callerCertPEM := eccentric.PEMEncode(callerCert)
	callerFPCACertPEM := eccentric.PEMEncode(callerFPCACert)

	return listener {
		Endpoint: endpoint,
		ListenerCN: ourCreds.CN,
		ListenerTLSCertPEM: ourCreds.Cert,
		ListenerTLSPrivKeyPEM: ourCreds.Priv,

		CallerCN: callerCN,
		CallerCertPEM: callerCertPEM,
		CallerFPCACertPEM: callerFPCACertPEM,
	}
}


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
func startAllListeners() {
	listeners, err := getAllListeners()
	check(err)

	for _, listener := range listeners {
		startListener(listener)
	}
}


func startListener(listener listener) {
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

	netl, err := net.Listen("tcp", listener.Endpoint)
	check(err)
	log.Printf("Started Listener at %v", listener.Endpoint)
	go AwaitIncomingConnection(netl, listenerConfig, listener.CallerCN)
}


// Await Incoming connection on the given net.Listener.
func AwaitIncomingConnection(listener net.Listener, serverConfig *tls.Config, userCN string) {
	log.Printf("Awaiting connections on %v", listener.Addr())

	for {
		conn, err := listener.Accept()
		check(err)
		go answerIncomingConnection(conn, serverConfig, userCN)
	}
}


// Answer the incoming connection, verify the identity of the remote party.
// Hang up if it is not the one we expect.
func answerIncomingConnection(conn net.Conn, serverConfig *tls.Config, userCN string) {
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
	// Hand the socket to the user
	// return tlsconn

	// Echo all incoming data in small chunks.
	buf := make([]byte, 8)
	n, err := tlsconn.Read(buf)
	for ;; {
		if err != nil { break; }

		log.Printf("Echoing: %v [%v]", n, string(buf[:n]))
		_, err = tlsconn.Write(buf[:n])
		check(err)

		// loop
		n, err = tlsconn.Read(buf)
	}
	tlsconn.Close()
}
