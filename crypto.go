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
	"io"
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
	err, stdout, _ := run(strings.NewReader(cleartext), 
		"openssl", "smime", "-encrypt", "-aes128", "-binary", "-outform", "DER", certFileName)
	if err != nil {
		log.Fatal(err)
	}
	cipherDER := stdout.Bytes()
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
	err, stdout, stderr := run(bytes.NewReader(cipherBlock.Bytes),
		"openssl", "smime", "-decrypt", "-binary", "-inform", "DER", "-inkey", keyFileName)
	if err != nil {
		return fmt.Sprintf("Error decrypting message. Openssl says: %s\n", stderr.String())
	}
	cleartext := stdout.String()
	return cleartext
}

// Sign a message
func Sign(privkeyPEM []byte, certPEM []byte, message string) (string, error) {
	log.Printf("signing %v\n", message)
	if len(message) == 0 {
		return "", errors.New("Cannot sign empty message")
	}

	keyFileName := makeTempfile("ecca-key-", privkeyPEM)
	defer os.Remove(keyFileName)

	certFileName := makeTempfile("ecca-cert-", certPEM)
	defer os.Remove(certFileName)
	err, stdout, stderr := run(strings.NewReader(message), 
		"openssl", "smime", "-sign", "-signer", certFileName,  "-inkey", keyFileName)
	if err != nil {
		return "", errors.New(fmt.Sprintf("Error decrypting message. Openssl says: %s\n", stderr.String()))
	}
	signature := stdout.String()
	return signature, nil
}

// Verify the message
// Return a boolean whether the message is signed by the signature.
func Verify(message string, signature string, caChainPEM []byte) (bool, string) {
	log.Printf("verifying\n")
	//idFilename := makeTempfile("ecca-id-", idPEM)
	//defer os.Remove(idFilename)
	caFilename := makeTempfile("ecca-ca-", caChainPEM)
	defer os.Remove(caFilename)
	// TODO: create template to merge message and signature in a valid openssl smime like format 
	err, stdout, stderr := run(strings.NewReader(signature), 
		"openssl", "smime", "-verify",  "-CAfile", caFilename)
//		"openssl", "smime", "-verify",  "-CAfile", "./Cryptoblog-chain.pem")
	if err != nil {
		log.Printf("Error verifying message. Openssl says: %s\n", stderr.String())
		return false, stderr.String() // return error message for now.
	}
	// Note: with openssl smime signing, the true message is in the signature, we return what we get back from openssl 
	// TODO: return message == stdout.String(), plus "error message in case it is false"
	return true, stdout.String() // or Bytes()
}

func run(stdin io.Reader, command string, args ... string) (error, bytes.Buffer, bytes.Buffer) {
	runner := exec.Command(command, args...)
	runner.Stdin = stdin
 	var stdout bytes.Buffer
	var stderr bytes.Buffer
	runner.Stdout = &stdout
	runner.Stderr = &stderr
	err := runner.Run()
	if err != nil {
		log.Printf("Error with running command: \"%v %v\"\nerror is: %v\nstderr is: %v\n", command, args, err, stderr.String())
	}
	return err, stdout, stderr
}

// Fetch the identity (users' client certificate) from the signed message.
func FetchIdentity(signature string) (bytes.Buffer, error) {
	// log.Printf("fetching identity\n")
	err, pk7, stderr := run(strings.NewReader(signature), 
		"openssl", "smime", "-pk7out")
	if err != nil {
		log.Fatal(stderr.String()) 
		// this dies here.
	}
	// pipe the pk7 data to extract the user certificate
	err, cert, stderr := run(bytes.NewReader(pk7.Bytes()),
		"openssl", "pkcs7", "-print_certs")
	if err != nil {
		log.Fatal(stderr.String()) 
		// this dies here too.
	}
	return cert, nil;
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

