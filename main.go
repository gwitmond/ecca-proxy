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
	//"fmt"
	"flag"
	"net/http"
	"net/url"
	"time"
	"crypto/x509"
	"crypto/tls"
	MathRand   "math/rand"
	"io/ioutil"
	"bytes"
	"github.com/jteeuwen/go-pkg-xmlx"
	// "dnssec"  // TODO fork dnssec.go into separate package
)

// map between sitename and the url where to sign up for a 
var registerURLmap = map[string]string{}


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
	
	
	// Decode any messages when we have the "Eccentric-Authentication" header
	proxy.OnResponse().DoFunc(DecodeMessages)

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
			certificateURL := req.Form.Get("certificate_url")
			// silly 'encryption' to see if this works

			certURL, err := url.Parse(certificateURL)
			if err != nil {
				log.Println("error is ", err)
				return nil, nil
			}

			certHostname := getHostname(certURL.Host)
			client, err := makeClient(certHostname)
			if err != nil {
				log.Println("error is ", err)
				return nil, nil
			}

			ciphertext := POSTencrypt(client, certificateURL, cleartext)
			req.Form.Set("ciphertext", ciphertext)

			client2, err := makeClient(req.URL.Host)
			if err != nil {
				log.Println("error is ", err)
				return nil, nil
			}

			resp, err := client2.PostForm(req.URL.String(), req.Form)
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

// makeClient creates a http.Client struct with expected server CA-certficate configured.
// host is name[:port]
func makeClient(host string) (*http.Client, error) {
	var caCert *x509.Certificate
	var err error
	serverCred, haveIt := getServerCreds(host)
	if haveIt == true {
		// use cached certificate from previous connections.
		caCert = serverCred.caCert
	} else {
		// Get and cache server certificate from DNSSEC/DANE.
		caCert, err = GetCACert(getHostname(host))
		if err != nil { return nil, err }
		setServerCreds(host, serverCert{
			caCert: caCert,
		})
	}

	// create new client config at each connection 
	// just to make sure that we don't reuse previously used certificates when a user changes accounts
	// TODO: verify if we can change client certificates in a transport struct without reusing an
	// existing user connection. We don't want to leak the fact that these certificates belong to
	// the same person.
	tr := makeCertConfig(getHostname(host), caCert)
	
	// Get the current active account and log in with it if we have it.
	// Otherwise, just do without client certificate
	cred := getLoggedInCreds(host)
	if cred != nil {
		cert, err := tls.X509KeyPair(cred.cert, cred.priv)
		if err != nil { return nil, err }
		tr.TLSClientConfig.Certificates = []tls.Certificate{cert}
	}
	client := &http.Client{Transport: tr}
	return client, nil
}

// fetchRequest fetches the original users' request.
// adds client certificate to authenticate
func fetchRequest(req *http.Request, ctx *goproxy.ProxyCtx) (*http.Response, error) {
	// clean up the recycled header we got from the user
	req.RequestURI="" 
		
	client, err := makeClient(req.URL.Host)
	if err != nil { return nil, err }

	log.Printf("Connecting to: %s", req.URL.String())
	resp, err := client.Do(req)
	if err != nil { return nil, err }

// The rest of this function should go in a separate Response handler..
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

	// remember registerURL for the signup-phase
	registerURLmap[req.Host] = auth["register"]

	resp = redirectToSelector(req)
	return resp, nil
}





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


// DecodeMessages decodes any <message><ciphertext> tags and places the result in <cleartext>
func DecodeMessages(resp *http.Response, ctx *goproxy.ProxyCtx) *http.Response {
	if resp.Header.Get("Eccentric-Authentication") != "" {
		println("DecodeMessages response handler has header: ", resp.Header.Get("Eccentric-Authentication"))
		// get the users' Private key for this CN and hostname
		cred := getLoggedInCreds(ctx.Req.URL.Host)
		if cred == nil { 
			// we are not logged in, we don't have private keys, 
			// we cannot decode, return reponse unchanged
			return resp 
		}
		
		// Parse the response body and decode the messages from //ecca_message/ciphertext
		// store the decoded response in //ecca_message/cleartext
		doc := xmlx.New()
		err := doc.LoadStream(resp.Body, nil)
		check(err)

		list := doc.SelectNodes("", "ecca_message")
		log.Printf("list is: %#v\n", list)
		
		for _, message := range list {
			ciphertext := message.S("", "ciphertext")
			cleartext := decrypt(ciphertext, cred.priv)
			
			cleartextNode := message.SelectNode("", "cleartext")
			cleartextNode.Value = cleartext
		}
		
		doc.SaveDocType = false
		body := doc.SaveBytes()
		resp.Body = ioutil.NopCloser(bytes.NewReader(body))
		return resp
	}
	return resp
}


// Initialise math.rand seed. Otherwise it behaves as math.seed(1). ouch..
func init() {
	MathRand.Seed(time.Now().UnixNano())	
}

