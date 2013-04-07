// Ecca Authentication Proxy
//
// Handles Eccentric Authentication in a web proxy for browsers.
//
// Copyright 2013, Guido Witmond <guido@witmond.nl>
// Licensed under AGPL v3 or later. See LICENSE

package main // eccaproxy

import (
	//"log"
	"bytes"
	"encoding/gob"
	"./gocask"
)

// This file contains the data storage bits

var gocaskFile = "ecca-proxy-gocask-db"
var gocaskDB     *gocask.Gocask          // there is only one datastore, for now

func init() {
	var err error
 	gocaskDB, err = gocask.NewGocask(gocaskFile)
 	check(err)
}

func put(key string, creds []credentials) {
	err := gocaskDB.Put(key, gobencode(creds))
	check(err)
}

func get(key string) (creds []credentials) {
 	value, err := gocaskDB.Get(key)
 	if err == gocask.ErrKeyNotFound { return } // return empty
 	return gobdecode(value)
}

func getKeys() (keys []string) {
	return gocaskDB.GetKeys()
}


// Encode and decode with Gob. 
// credentials are defined in account.go
func gobencode(in []credentials) ([]byte) {
	var gobv bytes.Buffer
	enc := gob.NewEncoder(&gobv)
	err := enc.Encode(in)
	check(err)
	return gobv.Bytes()
}

func gobdecode(in []byte) (creds []credentials) {
	dec := gob.NewDecoder(bytes.NewBuffer(in))
	err := dec.Decode(&creds)
	check(err)
	return // decoded creds
}


// This is the old interface to the rest of ecca-proxy.
// It used to talk to sqlite3. See below.
// Now it has been reimplemented with the K/V interface above.

// Add a credential to the list of credentials for the host.
// People can have multiple accounts a host.
func setCredentials(cred credentials) {
	hostname := cred.Hostname
	
	creds := get(hostname) // creds, exists := kv[hostname]
	creds = append(creds, cred)
	put(hostname, creds)  // kv[hostname] = creds
}

func getAllCreds () (all []credentials) {
	keys := getKeys()
	for _, key := range keys {
		for _, cred := range get(key) {
			all = append(all, cred)
		}
	}
	return // all
}

func getCreds (hostname string) (creds []credentials) {
	return get(hostname)
}

// get a credential for a hostname, cn pair
func getCred (hostname string, cn string) (*credentials) {
	creds := getCreds(hostname)
	for _, cred := range creds {
		if cred.CN == cn {
			return &cred
		}
	}
	return nil // no matches
}



// Here is the old sqlite implementation as reference.
// The problem is that this gosqlite library requires a too recent version
// of libsqlite3. Only recent Debian Wheezy and Ubuntu 12.10 had them.
// Others got a nasty error. That's why I took it out for that clumsy K/V 'solution' --GW.

// import "github.com/gwenn/gosqlite"


// Add a credential to the list of credentials for the host.
// People can have multiple accounts a host.
// func setCredentials(cred credentials) {
// 	accountSt, err := eccaDB.Prepare("INSERT INTO accounts (hostname, realm, cn, certPEM, privkeyPEM) values (?, ?, ?, ?, ?)")
// 	check(err)
// 	defer accountSt.Finalize()

// 	count, err := accountSt.Insert(cred.Hostname, cred.realm, cred.CN, cred.cert, cred.priv)
// 	check(err)
// 	log.Println("Inserted %d rows", count)
// }

// func getAllCreds () ([]credentials) {
// 	accountSel, err := eccaDB.Prepare("SELECT hostname, realm, cn, certPEM, privkeyPEM FROM accounts order by hostname, cn")
// 	check(err)
// 	defer accountSel.Finalize()
	
// 	var creds []credentials
// 	err = accountSel.Select(func(stmt *sqlite.Stmt) (err error) {
// 		var cred credentials
// 		var er error
// 		er = stmt.Scan(&cred.Hostname, &cred.realm, &cred.CN, &cred.cert, &cred.priv)
// 		check(er)
// 		creds = append(creds, cred)
// 		return
// 	})
// 	check(err)
// 	return creds
// }

// func getCreds (hostname string) ([]credentials) {
// 	accountSel, err := eccaDB.Prepare("SELECT hostname, realm, cn, certPEM, privkeyPEM FROM accounts WHERE hostname = ?")
// 	check(err)
// 	defer accountSel.Finalize()
	
// 	var creds []credentials
// 	err = accountSel.Select(func(stmt *sqlite.Stmt) (err error) {
// 		var cred credentials
// 		var er error
// 		er = stmt.Scan(&cred.Hostname, &cred.realm, &cred.CN, &cred.cert, &cred.priv)
// 		check(er)
// 		creds = append(creds, cred)
// 		return
// 	}, hostname)
// 	check(err)
// 	return creds
// }

// // get a credential for a hostname, cn pair
// func getCred (hostname string, cn string) (*credentials) {
// 	accountSel, err := eccaDB.Prepare("SELECT hostname, realm, cn, certPEM, privkeyPEM FROM accounts WHERE hostname = ? and cn = ?")
// 	check(err)
// 	defer accountSel.Finalize()
	
// 	var creds []credentials
// 	err = accountSel.Select(func(stmt *sqlite.Stmt) (err error) {
// 		var cred credentials
// 		var er error
// 		er = stmt.Scan(&cred.Hostname, &cred.realm, &cred.CN, &cred.cert, &cred.priv)
// 		check(er)
// 		creds = append(creds, cred)
// 		return
// 	}, hostname, cn)
// 	check(err)
// 	if len(creds) == 1 {
// 		return &creds[0]
// 	} 
// 	return nil
// }



// var eccaDBFile = "eccadb.db"
// var eccaDB *sqlite.Conn

// func init() {
// 	var err error
// 	eccaDB, err = sqlite.Open(eccaDBFile)
// 	check(err)	
	
//	//err = eccaDB.Exec("CREATE TABLE servers (hostname TEXT, realm TEXT, registerURL TEXT, caCertPEM TEXT)")
//	// check(err) // ignore

//	err = eccaDB.Exec("CREATE TABLE accounts (hostname TEXT, realm TEXT, cn TEXT, certPEM TEXT, privkeyPEM)")
	// check(err) // ignore
//}
