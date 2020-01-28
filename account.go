// Ecca Authentication Proxy
//
// Handles Eccentric Authentication in a web proxy for browsers.
//
// Copyright 2013, Guido Witmond <guido@witmond.nl>
// Licensed under AGPL v3 or later. See LICENSE

package main // eccaproxy

import (
	"log"
	"crypto/x509"
	"crypto/rand"
	"encoding/hex"
	"strings"
)

// This file contains the users' accounts for Ecca.
// This is what we use to determine with what certificate to log in at a certain site.

// key the accounts on the hostname of the site.
// TODO: use the server CAcert-pubkey/hash from the tls-connection as the realm of the map.
// META TODO: learn how to get that CACert from the tls-connection
// META TODO2: the realm the value in the DANE/TLSA record!

//-------------------- server data

type serverCert struct {
	//realm       string   // the realm from the WWW-authenticate header
	//registerURL string   // The url of the CA-signer
	caCert      *x509.Certificate   // the server CA-cert (must be same at Site and CA-signer)
}

// there is one server cert per realm. ie, one CA per Ecca-domain.
var serverCerts = make(map[string]serverCert)

func setServerCreds (realm string, server serverCert) {
	serverCerts[realm] = server // just overwrite
}

func getServerCreds (realm string) (serverCert, bool) {
	cert, ok := serverCerts[realm]
	return cert, ok
}

//-------------------- client data
type credentials struct {
	Id	 int64		 // for the database
	Hostname string          // the hostname
	Realm    string          // the realm for these credentials.  (The part after the @@? )
	CN       string          // the username
	Cert     []byte          // the client certificate without private key
	Priv     []byte          // the private key that matches the certificate.
	Comment  string          // notes the user can add to the account
	Created  int64		 // unix timestamp due to DB driver (gorp)
	LastUsed int64		 // unix timestamp due to DB driver (gorp)
}

//-------------------- Logins
// logins tells which credentials to use for each host (one cred per host)
// logins["www.foo.corp"] = credentials{cn: "anonymous-fawkes", ...}
// we forget all logins when the proxy terminates.
var logins = make(map[string] credentials)

// return the credentials that's currently logged in at hostname
func getLoggedInCreds (host string) (*credentials) {
	hostname := strings.ToLower(getHostname(host))
	cred, exists := logins[hostname]
	if exists == false { return nil } // User is not logged in.
	return &cred
}


// Set the active account for each host we are connected to.
// From this moment, every connection to <hostname> will be identified by the cert for <cn>
// Limit host to just the hostname, not the host:port
// So there is only one user logged in at any hostname at a time.
func login(host string, cred credentials) {
	hostname := strings.ToLower(getHostname(host))
	logins[hostname] = cred
	log.Println("logging in ", cred.CN, " at ", hostname)
	updateLastUsedTime(cred)
}

func logout(host string) {
	hostname := getHostname(host)
	delete(logins, hostname)
}


//--------------------- Invitations
// Invitations use a Token to prevent web pages from writing fake invitations.
// Only properly encrypted and signed messages may introduce an invitation.
// That's how we are sure about the identity of the sender.
// And how we authenticate the inviter.

// Store map in memory. Create new tokens at next run.
var invitations = make(map[string] DCInvitation)

// storeInvitation creates a token and stores the invitation. Returns the token.
func storeInvitation(invitation *DCInvitation) string {
	token := makeToken()
	invitations[token] = *invitation
	return token
}

// makeToken: make a 8 byte random value and encodes it into a string
func makeToken() string {
	buf := make([]byte, 8)
	_, err := rand.Read(buf)
	check(err)
	token := hex.EncodeToString(buf)
	return token
}

// getInvitation retrieves an invitation for a token, or nil.
func getInvitation(token string) *DCInvitation {
	invitation, exists := invitations[token]
	if exists == false { return nil }
	return &invitation
}

//--------------------- Utils
// Poor mans assert()
func check (err error) {
	if err != nil {
		log.Fatal("Error is: ", err)
	}
}
