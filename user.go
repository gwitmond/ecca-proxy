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
	"bytes"
	"net/http"
	"net/url"
	"io/ioutil"
	"html/template"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"strconv"
	"regexp"
	CryptoRand "crypto/rand"
	MathRand   "math/rand"
)

// Global config
var eccaHandlerHost = "ecca.handler"
var eccaHandlerPath = "/select"
var eccaManagerPath = "/manage"


func redirectToSelector(req *http.Request) (*http.Response) {
	redirectURL := url.URL{Scheme: "http", Host: eccaHandlerHost, Path: eccaHandlerPath}
	query := redirectURL.Query()
	query.Set("originalRequest", req.URL.String())
	redirectURL.RawQuery = query.Encode()		
	resp := makeRedirect(req, &redirectURL)
	return resp
}
	
//-------------------- Selector 
// Handle the user interaction to choose a certificate or create new ones.
// We show a simple form with the available credentials and allow the option to
// create a new one.

var selectTemplate = template.Must(template.New("select").Parse(
`<html>
<body>
<h1>401 - Eccentric Authentication required</h1>
<form method="POST" >
<p>Please select one of these identies {{ range . }} <input type="submit" name="login" value="{{ .CN }}">{{ else }} -none- {{ end }}<br>
<p>Or create a new one</p>
<input type="text" name="cn"><input type="submit" name="register" value="Register this name"></p><br>
<p>Or register anonymously: <input type="submit" name="anonymous" value="Anonymous"></p>
</form>
</body>
</html>`))

var embedTemplate = template.Must(template.New("embed").Parse(
`<html>
<body>
  <p>Ecca. You are logged in {{ .Hostname }} with {{ .CN }}. 
     Press here to logout: 
      <form method="POST" action="/manage">
       <input type="submit" name="logout" value="{{ .Hostname }}">
      </form></p>
<hr>
  <iframe src="{{ .URL }}" width="100%" height="100%">
    [Your user agent does not support frames or is currently configured
     not to display frames. 
     However, you may visit <a href="{{ .URL }}">{{ .URL }}</a>.
     <br>
     To log out:
      <form method="POST" action="/manage">
        <input type="submit" name="logout" value="{{ .Hostname }}">
       </form>]
  </iframe>
</body>
</html>`))

// eccaHandler: learn the users' selected account and set it as logged in.
// then redirect to original request (where the user want to go to)/
func eccaHandler (req *http.Request, ctx *goproxy.ProxyCtx) (*http.Request, *http.Response) {
	log.Println("\n\n\nRequest is ", req.Method, req.URL.String())
	
	switch req.URL.Path {
	case eccaHandlerPath: 
		return handleSelect(req, ctx)
	case eccaManagerPath:
		return handleManager(req, ctx)
	}
	log.Printf("Unexpected request: %#v\n", req)
	return nil, nil
}


func handleSelect (req *http.Request, ctx *goproxy.ProxyCtx) (*http.Request, *http.Response) {
	req.ParseForm()
	log.Printf("Form parameters are: %v\n", req.Form)
	var originalRequest = req.Form.Get("originalRequest")
	originalURL, err := url.Parse(originalRequest)
	if err != nil {
		log.Fatal("Error parsing originalRequest parameter: ", err)
	}
	log.Println("got param (originalRequest): ", originalRequest)

	switch req.Method {
	case "GET": 
		// User has no active logins.
		// Show available client certificates for URI.Host 
		creds := getCreds(originalURL.Host)
		buf := execTemplate(selectTemplate, "select", creds)
		resp := makeResponse(req, 200, "text/html", buf)
		return nil, resp
	case "POST":
		var cred *credentials
		if req.Form.Get("anonymous") != "" {
			// register with random cn
			cred = registerAnonymous(originalURL.Host)
		}
		
		if req.Form.Get("register") != "" {
			// register with given cn
			cn := req.Form.Get("cn")
			cred = registerCN(originalURL.Host, cn)
		}
		
		if cn := req.Form.Get("login"); cn != "" {
			cred = getCred(originalURL.Host, cn)
		}

		//TODO: make sure at least on of these actions above has success
		if (cred == nil) {
			log.Fatal("cred should not be nil")
		}
		login(originalURL.Host, *cred)

		// embed the original site in an iframe in our management frame.

		originalURL.Scheme = "http" // send users follow up requests back to us
		var data = map[string]string {
			"Hostname": originalURL.Host,
			"CN": cred.CN,
			"URL": originalURL.String(),
		}
		buf := execTemplate(embedTemplate, "embed", data)
		resp := makeResponse(req, 200, "text/html", buf)
		return nil, resp
	}
	log.Fatal("Unexpected method: ", req.Method)
	return nil, nil
}


// Register an anonymous account at the registerURL in the serverCredentials for hostname.
// Set serverCAcert from the caPEM field.
func registerAnonymous(hostname string) (*credentials){
	// create a unique userid
	cn := "anon-" + strconv.Itoa(int(MathRand.Int31()))
	return registerCN(hostname, cn)
}

// Strip the portnumber from the net.URL.Host string to get the hostname
var hostnameRE = regexp.MustCompile("^([^:]+):[0-9]+$")

// Register the named accountname at the sites' CA. Uses a new private key.	
func registerCN(hostname string, cn string) (*credentials) {
	log.Println("registring cn: ", cn, " for: ", hostname)

	priv, err := rsa.GenerateKey(CryptoRand.Reader, 1024)
	if err != nil {
		panic("cannot generate private key")
	}
	
	serverCred, _ := getServerCreds(hostname) // TODO, check ok-param == true
	regURL, err := url.Parse(serverCred.registerURL)
	check(err)

	servername := getFirst(hostnameRE.FindStringSubmatch(regURL.Host))
	log.Printf("Parsing %s gives %#v, we want: \n", serverCred.registerURL, regURL, servername)
	
	tr := makeCertConfig(servername, serverCred.caCert)		
	client := &http.Client{Transport: tr}
	
	cert := signupPubkey(client, serverCred.registerURL, cn, priv.PublicKey)

	var privPEM  bytes.Buffer
	pem.Encode(&privPEM, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)})
	creds := credentials{
		hostname: hostname,
		realm: "",
		CN: cn,	
		cert: cert,
		priv: privPEM.Bytes(),
	}
	// Register the data and set it as login certificate 
	// It's what the user would expect from signup.
	setCredentials(creds)
	return &creds
}


// Signup at the registerURL with the Public key and cn for username
// expect a 201-Created with a PEM certificate of
// a xxx-already-taken when the cn is already in use
func signupPubkey(client *http.Client, registerURL string, cn string, pub rsa.PublicKey) (cert []byte) {
	pubkey := publicKeyToPEM(pub)
	resp, err := client.PostForm(registerURL, url.Values{"cn": {cn}, "pubkey": {pubkey}})
	//TODO: check for several distict response.statuscodes
	if err != nil {
		log.Fatal("Error with SignPubkey request: ", err)
	}
	log.Printf("SignPubKey got response: %#v\n", resp)
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		panic("error reading response.body")
	}
	
	_ =  pemDecodeCertificate(body) // decode and panic if it fails to decode properly.
	return body
}

//------------------ Manager 
// show current logins and allow for logouts.

var showLoginTemplate = template.Must(template.New("showLogins").Parse(
`<html>
<body>
 <h1>Manage your Eccentric Authentication logins</h1>
 <p>This pages shows your active logins. You can log out of any.
  <form method="POST">
    <table>
      <tr><th>Host</th><th>Account</th><th>Action</th></tr>
    {{range $hostname, $cred := . }}
      <tr><td>{{ $hostname }}</td><td>{{ $cred.CN }}</td><td>Logout: <input type="submit" name="logout" value="{{ $hostname }}"></td></tr>
    {{ else }}
      <tr><td colspan="3">No logins anywhere</td></tr>
    {{ end }}
    </table>
  </form>
</body>
</html>`))


func handleManager (req *http.Request, ctx *goproxy.ProxyCtx) (*http.Request, *http.Response) {
	req.ParseForm()
	log.Printf("Form parameters are: %v\n", req.Form)

	switch req.Method {
	case "GET": 
		// Show current logins.
		buf  := execTemplate(showLoginTemplate, "showLogins", logins)
		resp := makeResponse(req, 200, "text/html", buf)
		log.Println("Show logins")
		return nil, resp
	case "POST":
		if hostname := req.Form.Get("logout"); hostname != "" {
			// log out from hostname 
			logout(hostname)
			log.Println("Logged out of ", hostname)
		}

		// redirect back to ourself
		resp := makeRedirect(req, req.URL)
		return nil, resp
	}
	
	log.Fatal("Unexpected method: ", req.Method)
	return nil, nil
}


//-- utils

func makeRedirect(req *http.Request, redirectURL *url.URL) (*http.Response) {
	log.Println("redirecting to ", redirectURL.String())
	resp := &http.Response{}
	resp.Request = req
	resp.TransferEncoding = req.TransferEncoding
	resp.Header = make(http.Header)
	resp.Header.Add("Content-Type", "text/html")
	resp.Header.Add("Location", redirectURL.String())
	resp.StatusCode = 302
	
	body := "Redirect to " + redirectURL.String()
	buf := bytes.NewBufferString(body)
        resp.ContentLength = int64(buf.Len())
        resp.Body = ioutil.NopCloser(buf)
        return resp
}


func makeResponse(req *http.Request, code int, contType string, buf *bytes.Buffer ) (*http.Response) {
	resp := &http.Response{}
	resp.Request = req
	resp.StatusCode = code
	resp.TransferEncoding = req.TransferEncoding
	resp.Header = make(http.Header)
	resp.Header.Add("Content-Type", contType)
	resp.Body = ioutil.NopCloser(buf)
	return resp
}


func execTemplate(template *template.Template, name string, data interface{}) (*bytes.Buffer) {
	buf := new(bytes.Buffer)
	err := template.ExecuteTemplate(buf, name, data)
	if err != nil {
		log.Fatal("error executing template: ", err)
	}
	return buf
}
