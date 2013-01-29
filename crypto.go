// Ecca Authentication Proxy
//
// Handles Eccentric Authentication in a web proxy for browsers.
//
// Copyright 2013, Guido Witmond <guido@witmond.nl>
// Licensed under GPL v3 or later.
	
package main // eccaproxy

import (
	"log"
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


func POSTencrypt(client *http.Client, certificateUrl, cleartext string) string {
	certPEM, err := fetchCertificatePEM(client, certificateUrl)
	check(err)
	cipherDER := encrypt(cleartext, certPEM)
	cipherPEM := pem.EncodeToMemory(&pem.Block{Type: "ECCA ENCRYPTED MESSAGE", Bytes: cipherDER})
	return string(cipherPEM)
}


// encrypt a cleartext message with the public key in the certificate of the recipient
func encrypt(cleartext string, certPEM []byte) []byte {
	certFile, err := ioutil.TempFile("", "ecca-cert-")
	certFileName := certFile.Name()
	certFile.Write(certPEM)
	certFile.Close()
	defer os.Remove(certFileName)
	
	enc := exec.Command("openssl", "smime", "-encrypt", "-aes128", "-binary", "-outform", "DER", certFileName)
	enc.Stdin = strings.NewReader(cleartext)
	var out bytes.Buffer
	enc.Stdout = &out
	err = enc.Run()
	if err != nil {
		log.Fatal(err)
	}
	log.Println("Data is encrypted")
	cipherDER := out.Bytes()
	return cipherDER
}

// fetchCertificate GETs the url and parses the page as a PEM encoded certificate.
func fetchCertificatePEM(client* http.Client, url string) ([]byte, error) {
	log.Printf("Fetching public key for %v\n", url)
	resp, err := client.Get(url)
	check(err)

	body, err := ioutil.ReadAll(resp.Body)
	check(err)

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



// Decrypting a message
func decrypt(cipherPEM string, privkeyPEM []byte) string {
	keyFile, err := ioutil.TempFile("", "ecca-key-")
	keyFileName := keyFile.Name()
	keyFile.Write(privkeyPEM)
	keyFile.Close()
	defer os.Remove(keyFileName)

	cipherBlock, _ := pem.Decode([]byte(cipherPEM))
	if cipherBlock.Type != "ECCA ENCRYPTED MESSAGE" {
		return "Error decoding ciphertext: expecing -----ECCA ENCRYPTED MESSAGE-----"
	}
	
	dec := exec.Command("openssl", "smime", "-decrypt", "-binary", "-inform", "DER", "-inkey", keyFileName)
	dec.Stdin = bytes.NewReader(cipherBlock.Bytes)
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	dec.Stdout = &stdout
	dec.Stderr = &stderr
	err = dec.Run()
	if err != nil {
		return fmt.Sprintf("Error decrypting message. Openssl says: %s\n", stderr.String())
	}
	cleartext := stdout.String()
	return cleartext
}
