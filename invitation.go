// Ecca Authentication Proxy
//
// Handles Eccentric Authentication in a web proxy for browsers.
//
// Invite users for a direct connection that not even the site knows about.
// Route through Tor and not even your isp knows about it.
//
// Copyright 2013, Guido Witmond <guido@witmond.nl>
// Licensed under AGPL v3 or later. See LICENSE

package main // eccaproxy

import (
	"bytes"
	"encoding/base64"
	"encoding/gob"
	"log"
)

type DCInvitation struct {
	Application     string   // what protocol to talk: chat/voice/video etc.
	InviteeCN       string   // who is invited to connect
	Endpoint        string   // where to connect to: ip:port, xyz.onion, etc
	ListenerCN      string   // expect listener to identify with this CN (tls: server name)
	ListenerFPCAPEM []byte   // signed by this CA.
}

func init() {
	gob.Register(DCInvitation{})
}


func encodeInvitation(invitation DCInvitation) string {
	var message bytes.Buffer
	encoder := gob.NewEncoder(&message)
	err := encoder.Encode(invitation)
	check(err)
	return base64.StdEncoding.EncodeToString(message.Bytes())
}


// parseInvitation takes a string and checks if it can be parsed as a base64 encoded DCInvitation
// Returns either the invitation or nil.
// We assume no other base64 encoded content.
func parseInvitation(cleartext string) (*DCInvitation) {
	message, err := base64.StdEncoding.DecodeString(cleartext)
	if err != nil {
		log.Printf("Decoding invitation failed: %#v, %#v", message, err)
		// not base64 encoded, it's probably a text message
		return nil
	}

	decoder := gob.NewDecoder(bytes.NewReader(message))
	var invitation DCInvitation
	err = decoder.Decode(&invitation)
	check(err) // die on error as we don't have other base64 encoded messages.
	// we can't show the binary data after base64 decoding either.

	return &invitation
}
