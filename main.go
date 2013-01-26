// Ecca Authentication Proxy
//
// Handles Eccentric Authentication in a web proxy for browsers.
//
// Copyright 2013, Guido Witmond <guido@witmond.nl>
// Licensed under GPL v3 or later.
	
package main // eccaproxy

import (
	"github.com/elazarl/goproxy"
	"log"
	"flag"
	"net/http"
	"time"
	"crypto/x509"
	"crypto/tls"
	MathRand   "math/rand"
	"io/ioutil"
	"bytes"
	// "dnssec"  // TODO fork dnssec.go into separate package
)

// IsRepsonseRedirected checks to see if the response has any set of the known redirect codes
func IsResponseRedirected(resp *http.Response) bool {
	return resp.StatusCode == 301 || resp.StatusCode == 302 ||
		resp.StatusCode == 303 || resp.StatusCode == 307
}

/* ChangeToHttp On redirect change the response location from https to http. 
   If so the client comes back to us, he doesn't have the keys we have. */
func ChangeToHttp(resp *http.Response, ctx *goproxy.ProxyCtx) *http.Response {
	if IsResponseRedirected(resp) {
		location, _ := resp.Location()
		if location != nil {
			if location.Scheme == "https" {
				location.Scheme = "http"
				resp.Header.Set("Location", location.String())
				println("ChangeToHttp response handler: ", ctx.Req.Host,"->",resp.Header.Get("Location"))
			}
		}
	}
	return resp
}

func main() {
	verbose := flag.Bool("v", false, "should every proxy request be logged to stdout")
	flag.Parse()
	proxy := goproxy.NewProxyHttpServer()
	proxy.Verbose = *verbose
	
	// Requests for eccaHandlerHost allow the user to select and create certificates
	// This handler sends a response
	proxy.OnRequest(goproxy.DstHostIs(eccaHandlerHost)).DoFunc(eccaHandler)
	
	// All other requests (where the user want to go to) are handled here.
	// When this needs an account, it redirect to eccaHandler above.
	proxy.OnRequest().DoFunc(eccaProxy)
	
	
	// Change the redirect location (from https) to http so the client gets back to us.
	proxy.OnResponse().DoFunc(ChangeToHttp)
	
	// run or die
	log.Fatal(http.ListenAndServe(":8000", proxy))
}

// eccaProxy: proxy the user requests and authenticate with the credentials we know.
func eccaProxy (req *http.Request, ctx *goproxy.ProxyCtx) (*http.Request, *http.Response) {
	log.Println("\n\n\nRequest is ", req.Method, req.URL.String())

	// set the scheme to https so we connect upstream securely
	if req.URL.Scheme == "http" {
		req.URL.Scheme = "https"
	}
	
	// Copy the body to when we need it untouched. We need to parse the POST parameters and that 
	// eats the buffer
	body, err := ioutil.ReadAll(req.Body)
	check(err)
	
	// give it back immedeately.
	req.Body = ioutil.NopCloser(bytes.NewReader(body))

	// Check for POST method with 'encrypt' param. 
	// transparantly encrypt the data.
	if req.Method == "POST" {
		req.ParseForm()  // eats req.Body
		req.Body = ioutil.NopCloser(bytes.NewReader(body)) // copy back in again
		if req.Form.Get("encrypt") == "required" {
			cleartext := req.Form.Get("cleartext")
			certificateUrl := req.Form.Get("certificate_url")
			// silly 'encryption' to see if this works
			ciphertext := reverseString(cleartext + certificateUrl)
			req.Form.Set("ciphertext", ciphertext)

			client, _ := makeClient(req)
			resp, err := client.PostForm(req.URL.String(), req.Form)
			if err != nil {
				log.Println("error is ", err)
				return nil, nil
			}
			return nil, resp
		}
	}

	resp, err := fetchRequest(req, ctx)


	if err != nil {
		log.Println("There was an error fetching the users' request: ", err)
		return req, goproxy.NewResponse(req,
			goproxy.ContentTypeText, http.StatusInternalServerError,
			"Some server error!")
	}
		
	log.Printf("response is %#v\n", resp) 
	return nil, resp // let goproxy send our response
}


// makeCertConfig creates a new Client Config struct with the given CA-Cert in PEM format
// set the TLS-SNI to servername
func makeCertConfig (servername string, caCert *x509.Certificate) (*http.Transport) {
	pool := x509.NewCertPool()
	pool.AddCert(caCert)
	tr := &http.Transport{ TLSClientConfig: &tls.Config{
		RootCAs: pool,
		ServerName: servername}}
	return tr
}

// makeClient creates a http client with expected server CA-certficate configured.
func makeClient(req *http.Request) (*http.Client, *x509.Certificate) {
	var caCert *x509.Certificate
	serverCred, haveIt := getServerCreds(req.URL.Host)
	if haveIt == true {
		// use cached certificate from previous connections.
		caCert = serverCred.caCert
	} else {
		// Get server certificate from DNSSEC/DANE.
		caCert = GetCACert(getHostname(req.URL.Host))
	}

	// create new client config at each connection 
	// just to make sure that we don't reuse previously used certificates when a user changes accounts
	// TODO: verify if we can change client certificates in a transport struct without reusing an
	// existing user connection. We don't want to leak the fact that these certificates belong to
	// the same person.
	tr := makeCertConfig(getHostname(req.URL.Host), caCert)
	
	// Get the current active account and log in with it if we have it.
	// Otherwise, just do without client certificate
	cred := getLoggedInCreds(req.URL.Host)
	if cred != nil {
		cert, err := tls.X509KeyPair(cred.cert, cred.priv)
		check(err)
		tr.TLSClientConfig.Certificates = []tls.Certificate{cert}
	}
	client := &http.Client{Transport: tr}
	return client, caCert // return the caCert so we can cache it, together with the www-autenticate data
}

// fetchRequest fetches the original users' request.
// adds client certificate to authenticate
func fetchRequest(req *http.Request, ctx *goproxy.ProxyCtx) (*http.Response, error) {
	// clean up the recycled header we got from the user
	req.RequestURI="" 
		
	client, caCert := makeClient(req)
	
	log.Printf("Connecting to: %s", req.URL.String())
	resp, err := client.Do(req)
	if err != nil {
		log.Println("error is ", err)
		return nil, err
	}

	// test if we need to authenticate.
	if resp.StatusCode != 401 {
		// nope, we're done. Exit here.
		return resp, nil
	}
	log.Printf("status code is 401\n")
	
	// We have an 401-authorization failed 
	// Test for a WWW-Authenticate: Ecca .... header.
	
	auth := ParseWWWAuthHeader(resp.Header.Get("Www-Authenticate"))
	if auth == nil {
		// No Ecca-authentication required. We're done. Exit here.
		log.Printf("No WWW-Auhtenticate: Ecca header, sending 401 response to client")
		return resp, nil
	}
	log.Printf("WWW-Authenticate: Ecca header found: %#v\n", auth)
	
	// Store the server CA credentials, we need them to log in to the CA-signer at
	// the signup-procedure.
	setServerCreds(ctx.Req.URL.Host, serverCert{
		// realm: auth["realm"], 
		registerURL: auth["register"],
		caCert: caCert,
	})
	
	resp = redirectToSelector(req)
	return resp, nil
}



// Initialise math.rand seed. Otherwise it behaves as math.seed(1). ouch..
func init() {
	MathRand.Seed(time.Now().UnixNano())	
}

// See rosettacode.org/wiki/Reverse_a_string#Go for better implementations
func reverseString(s string) string {
    r := make([]byte, len(s))
    for i := 0; i < len(s); i++ {
        r[i] = s[len(s)-1-i]
    }
    return string(r)
}