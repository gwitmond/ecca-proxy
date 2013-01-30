// Ecca Authentication Proxy
//
// Handles Eccentric Authentication in a web proxy for browsers.
//
// Copyright 2013, Guido Witmond <guido@witmond.nl>
// Licensed under GPL v3 or later.

package main // eccaproxy

import (
	"log"
	"crypto/x509"
	"github.com/gwenn/gosqlite"
)

// This file contains the users' accounts for Ecca. 
// This is what we use to determine with what certificate to log in at a certain site.

// key the accounts on the hostname of the site.
// TODO: use the server CAcert-pubkey/hash from the tls-connection as the realm of the map.
// META TODO: learn how to get that CACert from the tls-connection

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
	Hostname string          // the hostname
	realm    string          // the realm for these credentials. TODO: serverCA-hash
	CN       string          // the username
	cert     []byte          // the client certificate without private key
	priv     []byte          // the private key that matches the certificate.
}


// logins tells which credentials to use for each host (one cred per host)
// logins["www.foo.corp"] = credentials{cn: "anonymous-fawkes", ...}
// we forget all logins when the proxy terminates.
var logins = make(map[string] credentials)

// return the credentials that's currently logged in at hostname 
func getLoggedInCreds (hostname string) (*credentials) {
	cred, exists := logins[hostname]
	if exists == false { return nil } // User is not logged in. 
	return &cred
}

// Set the active account for each host we are connected to.
// From this moment, every connection to <hostname> will be identified by the cert for <cn>
func login(hostname string, cred credentials) {
	logins[hostname] = cred
	log.Println("logging in ", cred.CN, " at ", hostname)
}

func logout(hostname string) {
	delete(logins, hostname)
}

// Add a credential to the list of credentials for the host.
// People can have multiple accounts a host.
func setCredentials(cred credentials) {
	accountSt, err := eccaDB.Prepare("INSERT INTO accounts (hostname, realm, cn, certPEM, privkeyPEM) values (?, ?, ?, ?, ?)")
	check(err)
	defer accountSt.Finalize()

	count, err := accountSt.Insert(cred.Hostname, cred.realm, cred.CN, cred.cert, cred.priv)
	check(err)
	log.Println("Inserted %d rows", count)
}

func getAllCreds () ([]credentials) {
	accountSel, err := eccaDB.Prepare("SELECT hostname, realm, cn, certPEM, privkeyPEM FROM accounts order by hostname, cn")
	check(err)
	defer accountSel.Finalize()
	
	var creds []credentials
	err = accountSel.Select(func(stmt *sqlite.Stmt) (err error) {
		var cred credentials
		var er error
		er = stmt.Scan(&cred.Hostname, &cred.realm, &cred.CN, &cred.cert, &cred.priv)
		check(er)
		creds = append(creds, cred)
		return
	})
	check(err)
	return creds
}

func getCreds (hostname string) ([]credentials) {
	accountSel, err := eccaDB.Prepare("SELECT hostname, realm, cn, certPEM, privkeyPEM FROM accounts WHERE hostname = ?")
	check(err)
	defer accountSel.Finalize()
	
	var creds []credentials
	err = accountSel.Select(func(stmt *sqlite.Stmt) (err error) {
		var cred credentials
		var er error
		er = stmt.Scan(&cred.Hostname, &cred.realm, &cred.CN, &cred.cert, &cred.priv)
		check(er)
		creds = append(creds, cred)
		return
	}, hostname)
	check(err)
	return creds
}

// get a credential for a hostname, cn pair
func getCred (hostname string, cn string) (*credentials) {
	accountSel, err := eccaDB.Prepare("SELECT hostname, realm, cn, certPEM, privkeyPEM FROM accounts WHERE hostname = ? and cn = ?")
	check(err)
	defer accountSel.Finalize()
	
	var creds []credentials
	err = accountSel.Select(func(stmt *sqlite.Stmt) (err error) {
		var cred credentials
		var er error
		er = stmt.Scan(&cred.Hostname, &cred.realm, &cred.CN, &cred.cert, &cred.priv)
		check(er)
		creds = append(creds, cred)
		return
	}, hostname, cn)
	check(err)
	if len(creds) == 1 {
		return &creds[0]
	} 
	return nil
}



var eccaDBFile = "eccadb.db"
var eccaDB *sqlite.Conn

func init() {
	var err error
	eccaDB, err = sqlite.Open(eccaDBFile)
	check(err)	
	
	//err = eccaDB.Exec("CREATE TABLE servers (hostname TEXT, realm TEXT, registerURL TEXT, caCertPEM TEXT)")
	// check(err) // ignore

	err = eccaDB.Exec("CREATE TABLE accounts (hostname TEXT, realm TEXT, cn TEXT, certPEM TEXT, privkeyPEM)")
	// check(err) // ignore
}


// Poor mans assert()
func check (err error) {
	if err != nil {
		log.Fatal("Error is: ", err)
	}
}
