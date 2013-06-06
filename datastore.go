// Ecca Authentication Proxy
//
// Handles Eccentric Authentication in a web proxy for browsers.
//
// Copyright 2013, Guido Witmond <guido@witmond.nl>
// Licensed under AGPL v3 or later. See LICENSE

package main // eccaproxy

// This file contains the data storage bits

import (
	"log"
	"fmt"
	"os"
		
	// These are for the data storage
        "github.com/coopernurse/gorp"
        "database/sql"
        _ "github.com/mattn/go-sqlite3"
)


var dbmap *gorp.DbMap

func init() {
        db, err := sql.Open("sqlite3", "./proxy.sqlite3")
        check(err)
        dbmap = &gorp.DbMap{Db: db, Dialect: gorp.SqliteDialect{}}
        dbmap.AddTableWithName(credentials{}, "credentials")  // .SetKeys(false, "CN", "Realm")
	
        dbmap.CreateTables() // if not exists
        
        dbmap.TraceOn("[gorp]", log.New(os.Stdout, "myapp:", log.Lmicroseconds)) 
}


// Add a credential to the list of credentials for the host.
// People can have multiple accounts a host.
func setCredentials(cred credentials) {
	check(dbmap.Insert(&cred))
}

// Just get all credentials... (sorted by getCredentials)
func getAllCreds () ([]credentials) {
	creds, err := getCredentials()
	check(err)
	return creds
}

// Get list of all creds for a specified hostname
func getCreds (hostname string) ([]credentials) {
	creds, err := getCredentials(hostname)
	check(err)
	return creds
}

// get a credential for a hostname, cn pair.
// or return nil.
// die if there is more than one! TODO: Change that to a juicy error stating that the FPCA is dishonest.
func getCred (hostname string, cn string) (*credentials) {
	creds, err := getCredentials(hostname, cn)
	check(err)
	switch len(creds) {
	case  0:
		return nil
	case 1:
		return &creds[0]
	default: panic(fmt.Sprintf("Too many credentials for host: %s, CN: %s", hostname, cn))
	}
}

// getCredentials, all of them, all for a host, or a single one.
func getCredentials(args... interface{}) ([]credentials, error) {
        var query string
        switch {
        case len(args) == 0:
                query = "SELECT * FROM credentials"
                
        case len(args) == 1:
                query = "SELECT * FROM credentials WHERE hostname = ?"
                
        case len(args) == 2:
                query = "SELECT * FROM credentials WHERE hostname = ? AND cn = ?"
        }

	query += " ORDER BY hostname, cn"
 
        creds, err := dbmap.Select(credentials{}, query, args...)
        if err != nil { return nil, err }

	// ugly boilerplate. Can this be done better?
	var res = make([]credentials, len(creds))
	for i, e := range creds {
		res[i] = *e.(*credentials)
	}
	return res, nil
}
