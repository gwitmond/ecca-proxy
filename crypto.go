// Ecca Authentication Proxy
//
// Handles Eccentric Authentication in a web proxy for browsers.
//
// Copyright 2013, Guido Witmond <guido@witmond.nl>
// Licensed under AGPL v3 or later. See LICENSE
	
package main // eccaproxy

import (
	"log"
	"fmt"
	"net/http"
	"crypto/x509"
	"io/ioutil"
	"encoding/pem"
	"errors"
	"bytes"
	"os"
	"os/exec"
	"strings"
)

// TODO: move this to proxy.go (or separate file)
func POSTencrypt(client *http.Client, certificateUrl, cleartext string) []byte {
	certPEM, err := fetchCertificatePEM(client, certificateUrl)
	check(err)
	cipherPEM := Encrypt(cleartext, certPEM)
	return cipherPEM
}

// Encrypt a cleartext message with the public key in the certificate of the recipient using openssl
func Encrypt(cleartext string, certPEM []byte) []byte {
	certFileName := makeTempfile("ecca-cert", certPEM)
	defer os.Remove(certFileName)
	
	enc := exec.Command("openssl", "smime", "-encrypt", "-aes128", "-binary", "-outform", "DER", certFileName)
	enc.Stdin = strings.NewReader(cleartext)
	var out bytes.Buffer
	enc.Stdout = &out
	err := enc.Run()
	if err != nil {
		log.Fatal(err)
	}
	cipherDER := out.Bytes()
	cipherPEM := pem.EncodeToMemory(&pem.Block{Type: "ECCA ENCRYPTED MESSAGE", Bytes: cipherDER})
	return cipherPEM
}

// TODO: move it along with POSTencrypt.
// fetchCertificate GETs the url and parses the page as a PEM encoded certificate.
func fetchCertificatePEM(client* http.Client, url string) ([]byte, error) {
	log.Printf("Fetching public key for %v\n", url)
	resp, err := client.Get(url)
	check(err)

	body, err := ioutil.ReadAll(resp.Body)
	check(err)

	log.Printf("Received: %q\n", body)

	// decode pem..., 
	pemBlock, _ := pem.Decode(body)

	// check type..., 
	if pemBlock.Type != "CERTIFICATE" {
		return nil, errors.New("Did not receive a PEM encoded certificate")
	}

	// parse der to validate the data...,
	_, err = x509.ParseCertificate(pemBlock.Bytes)
	check(err)

	// but return the PEM so we can copy it to disk for /usr/bin/openssl
	return body, nil
}

// Decrypting a message using openssl
func Decrypt(cipherPEM []byte, privkeyPEM []byte) string {
	
	if len(cipherPEM) == 0 {
		return "Error, no secret message here. In fact, nothing at all."
	}
	cipherBlock, _ := pem.Decode(cipherPEM)
	if cipherBlock == nil {
		return "Error, no secret message here. Nothing we could recognize."
	}
	if cipherBlock.Type != "ECCA ENCRYPTED MESSAGE" {
		return "Error decoding secret message: expecing -----ECCA ENCRYPTED MESSAGE-----"
	}

	keyFileName := makeTempfile("ecca-key-", privkeyPEM)
	defer os.Remove(keyFileName)

	dec := exec.Command("openssl", "smime", "-decrypt", "-binary", "-inform", "DER", "-inkey", keyFileName)
	dec.Stdin = bytes.NewReader(cipherBlock.Bytes)
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	dec.Stdout = &stdout
	dec.Stderr = &stderr
	err := dec.Run()
	if err != nil {
		return fmt.Sprintf("Error decrypting message. Openssl says: %s\n", stderr.String())
	}
	cleartext := stdout.String()
	return cleartext
}

// Sign a message

func Sign(privkeyPEM []byte, certPEM []byte, message string) string {
	keyFileName := makeTempfile("ecca-key-", privkeyPEM)
	defer os.Remove(keyFileName)

	certFileName := makeTempfile("ecca-cert-", certPEM)
	defer os.Remove(certFileName)

	exc := exec.Command("openssl", "smime", "-sign", "-signer", certFileName,  "-inkey", keyFileName)
	exc.Stdin = strings.NewReader(message)
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	exc.Stdout = &stdout
	exc.Stderr = &stderr
	err := exc.Run()
	if err != nil {
		return fmt.Sprintf("Error decrypting message. Openssl says: %s\n", stderr.String())
	}
	signature := stdout.String()
	return signature
}

// Verify the message
// Return a boolean wheter the message is signed by the signature.
// TODO: verify the certificate.... (now just -noverify to just check the sha1. and trust the server for the sender information.
// TODO: This we need to do with embedded encryption, not with openssl.
func Verify(message string, signature string) (bool, string) {
	log.Printf("verifying\n")
	// TODO: create template to merge message and signature in a valid openssl smime like format 
	ver := exec.Command("openssl", "smime", "-verify", "-noverify")
	ver.Stdin = strings.NewReader(signature) // TODO: change message for template 
 	var stdout bytes.Buffer
	var stderr bytes.Buffer
	ver.Stdout = &stdout
	ver.Stderr = &stderr
	err := ver.Run()
	if err != nil {
		log.Printf("Error verifying message. Openssl says: %s\n", stderr.String())
		return false, stderr.String() // return error message for now.
	}
	// Note: with openssl smime signing, the true message is in the signature, we return what we get back from openssl 
	// TODO: return message == stdout.String(), plus "error message in case it is false"
	return true, stdout.String() // or Bytes()
}


// make a tempfile with given data.
// return the filename, caller needs to defer.os.Remove it.
func makeTempfile(prefix string, data []byte) string {
	tempFile, err := ioutil.TempFile("", prefix)
	check(err) // die on error
	tempFileName := tempFile.Name()
	tempFile.Write(data)
	tempFile.Close()
	return tempFileName
}

