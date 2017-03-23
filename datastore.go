// Ecca Authentication Proxy
//
// Handles Eccentric Authentication in a web proxy for browsers.
//
// Copyright 2013, Guido Witmond <guido@witmond.nl>
// Licensed under AGPL v3 or later. See LICENSE

package main // eccaproxy

// This file contains the data storage bits

import (
	"fmt"
	// These are for the data storage
	"gopkg.in/gorp.v1"
        "database/sql"
        _ "github.com/mattn/go-sqlite3"
	"time"
)


var dbmap *gorp.DbMap

func init_datastore(datastore string) {
        db, err := sql.Open("sqlite3", datastore)
        check(err)
        dbmap = &gorp.DbMap{Db: db, Dialect: gorp.SqliteDialect{}}
        dbmap.AddTableWithName(credentials{}, "credentials").SetKeys(true, "Id")
	dbmap.AddTableWithName(listener{}, "listeners")
        dbmap.CreateTables() // if not exists

        //dbmap.TraceOn("[gorp]", log.New(os.Stdout, "myapp:", log.Lmicroseconds))
}


// Add a credential to the list of credentials for the host.
// People can have multiple accounts a host.
func setCredentials(cred credentials) {
	check(dbmap.Insert(&cred))
}


func updateLastUsedTime(cred credentials) {

	cred.LastUsed = time.Now().Unix()
	_, err := dbmap.Update(&cred)
	check(err)
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
	case 0:
		return nil
	case 1:
		return &creds[0]
	default: panic(fmt.Sprintf("Too many credentials for host: %s, CN: %s", hostname, cn))
	}
}

// getCredentials, all of them, all for a host, or a single one.
func getCredentials(args... interface{}) (creds []credentials, err error) {
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

        _, err = dbmap.Select(&creds, query, args...)
        if err != nil { return nil, err }
	return // creds
}

// Listeners

func storeListener(listener listener) {
	check(dbmap.Insert(&listener))
}

// Just get all listeners
func getAllListeners () ([]listener, error) {
	query := "SELECT * FROM listeners"

        dbls, err := dbmap.Select(listener{}, query)
        if err != nil { return nil, err }

	// ugly boilerplate. Can this be done better?
	var res = make([]listener, len(dbls))
	for i, e := range dbls {
		res[i] = *e.(*listener)
	}
	return res, nil
}


type AllDetails struct {
	Hostname    string
	ListenerCN  string
	CallerCN    *string
	Application *string
}


// get all details (realms), hosts, accounts, callers, application for all records.
func getAllDetails() (map[string][]AllDetails) {
	query := `SELECT cr.hostname AS hostname, cr.cn AS listenerCN,
                  li.callerCN AS callerCN, li.application AS application
                  FROM credentials cr LEFT OUTER JOIN listeners li ON cr.cn = li.listenercn
                  ORDER BY cr.hostname, cr.cn, li.callercn, li.application;`
	var list []AllDetails
	_, err := dbmap.Select(&list, query)
	check(err)

	details := map[string][]AllDetails{}
	for _, item := range list {
		hostname := item.Hostname
		details[hostname] = append(details[hostname],item)
	}
	return details
}

