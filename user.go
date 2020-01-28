// Ecca Authentication Proxy
//
// Handles Eccentric Authentication in a web proxy for browsers.
//
// Copyright 2013, Guido Witmond <guido@witmond.nl>
// Licensed under AGPL v3 or later. See LICENSE

package main // eccaproxy

import (
	"github.com/elazarl/goproxy"
	"log"
	"fmt"
	"errors"
	"bytes"
	"net"
	"net/http"
	"net/url"
	"io"
	"io/ioutil"
	"strings"
	"html/template"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"encoding/json"
	"time"
	"os/exec"
	"path"
	"regexp"
	"strconv"
	CryptoRand "crypto/rand"
	"github.com/gwitmond/eccentric-authentication" // package eccentric
	"github.com/gwitmond/socks4a"
)

// Global config
var eccaHandlerHost = "ecca.handler"
var eccaHandlerPath = "/select"
var eccaManagerPath = "/manage"
var eccaShowCertPath= "/showcert"
var eccaStaticPath  = "/static"
var eccaDirectConnectionsPath= "/direct-connections"
var eccaDialDirectConnectionPath= "/dial-direct-connection"
var eccaLongpollPath = "/longpoll"

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


// eccaHandler: learn the users' selected account and set it as logged in.
// then redirect to original request (where the user want to go to)/
func eccaHandler (req *http.Request, ctx *goproxy.ProxyCtx) (*http.Request, *http.Response) {
	log.Println("\n\n\nRequest is ", req.Method, req.URL.String())

	switch req.URL.Path {
	case eccaHandlerPath:
		return handleSelect(req, ctx)
	case eccaManagerPath:
		return handleManager(req, ctx)
	case eccaDirectConnectionsPath:
		return handleDirectConnections(req, ctx)
	case eccaDialDirectConnectionPath:
		return handleDialDirectConnection(req, ctx)
        case eccaStaticPath:
                return serveStaticFile(req, ctx)
	case eccaLongpollPath:
	        return handleLongpoll(req, ctx)
	// case eccaShowCertPath:
	// 	return handleShowCert(req, ctx)
	}
	log.Printf("Unexpected request: %#v\n", req)
	return nil, nil
}

func getContentType(staticFileName string) string {
	var contentType string

	switch staticFileName[:3] {
	case "css":
		contentType = "text/css"
	case "js/":
		contentType = "text/javascript"
	case "img":
		switch staticFileName[len(staticFileName)-3:] {
		case "png":
			contentType = "image/png"
		default:
			contentType = "image/unknown"
		}
	default:
		contentType = "text/plain"
	}
	return contentType
}

var templates *template.Template
var templatesList = []string{
    "templates/select.html",
    "templates/embed.html",
    "templates/showLogins.html",
    "templates/directConnections.html",
    "templates/navbar.html",
    "templates/head.html",
};

var funcMap = template.FuncMap{
		// The name "mod" is what the function will be called in the template text.
		"mod": func(a int, b int) int {
			return a % b
		},
		"unixToDateTime": func(timestamp int64) string {
			return time.Unix(timestamp, 0).Format("Monday 02 January 2006 15:04")
		},
		"isEq": func(a *string, b string) bool {
			if a == nil {
				return false
			}
			return *a == b
		},
	}

func initialiseTemplates(baseDir string) {
	// point the templates to baseDir/.../templates/<name>
	var temps = []string{}
	for _, templ := range templatesList {
	    temps = append(temps, path.Join(baseDir, templ))
	}
	templates = template.Must(template.New("templates").Funcs(funcMap).ParseFiles(temps...))
}


func serveStaticFile(req *http.Request, ctx *goproxy.ProxyCtx) (*http.Request, *http.Response) {
	req.ParseForm()
	var staticFile = req.Form.Get("file")

	switch req.Method {
	case "GET":
	        // path.Join cleans the path of ../ rubbish
	        filename := path.Join(baseDir, "static", staticFile)
		// test for that rubbish by verifying the prefix
		if strings.HasPrefix(filename, path.Join(baseDir, "static")) {
		    contents, err := ioutil.ReadFile(filename)
		    if err != nil {
			log.Printf("error reading file: %v; error: %v\n", filename, err)
			resp := makeResponse(req, 404, "text/plain", bytes.NewBuffer([]byte("Not Found")))
			return nil, resp
		    } else {
		        contentType := getContentType(staticFile)
		    	buf := bytes.NewBuffer(contents)
		    	resp := makeResponse(req, 200, contentType, buf)
		    	return nil, resp
		    }
		} else {
		    log.Printf("error invalid static filename: %v\n", staticFile)
		    // however, just send the same 404 message.
		    resp := makeResponse(req, 404, "text/plain", bytes.NewBuffer([]byte("Not Found")))
		    return nil, resp
		}
	}
	log.Printf("Unexpected method: %#v", req.Method)
	return nil, nil
}

// increase this amount if you have more than 100 friends calling at the same time.
var lpchan = make(chan *caller, 100)

func signalFrontEnd(caller *caller) {
     lpchan <- caller
}

func handleLongpoll (req *http.Request, ctx *goproxy.ProxyCtx) (*http.Request, *http.Response) {
    timeout, err := strconv.Atoi(req.URL.Query().Get("timeout"))
    if err != nil || timeout > 180000 || timeout < 0 {
        timeout = 60000; // default 60 seconds
    }

    // Timeout before the client does.
    // It compensates for transmission delays
    // and prevents races where we send a reply just after the client has timed out.
    // That would cause the client to miss an event.
    timeout = int(0.95 * float32(timeout))

    select {
    case caller := <- lpchan:
	json, err := json.Marshal(caller)
	check(err)
	resp := makeResponse(req, 200, "application/json", bytes.NewBuffer(json))
        return nil, resp
    case <- time.After(time.Duration(timeout) * time.Millisecond):
        resp := makeResponse(req, 404, "text/plain", bytes.NewBuffer([]byte("timeout")))
        return nil, resp
    }
}


func handleSelect (req *http.Request, ctx *goproxy.ProxyCtx) (*http.Request, *http.Response) {
	var originalURL *url.URL
	var err error
	req.ParseForm()
	log.Printf("Form parameters are: %v\n", req.Form)
	var originalRequest = req.Form.Get("originalRequest")
	originalURL, err = url.Parse(originalRequest)
	if err != nil {
		log.Fatal("Error parsing originalRequest parameter: ", err)
	}
	//log.Println("got param (originalRequest): ", originalRequest)

	switch req.Method {
	case "GET":
		// User has no active logins.
		// Show available client certificates for URI.Host
		creds := getCreds(originalURL.Host)
		buf := execTemplate(templates, "select.html", map[string]interface{}{"Creds": creds, "Hostname": originalURL.Host})
		resp := makeResponse(req, 200, "text/html", buf)
		return nil, resp
	case "POST":
		var cred *credentials

		comment := req.Form.Get("comment")

		if req.Form.Get("register") != "" {
			// register with given cn
			cn := req.Form.Get("register")
			cred, err = registerCN(originalURL.Host, cn, comment)
		}

		if cn := req.Form.Get("login"); cn != "" {
			cred = getCred(originalURL.Host, cn)
		}


		if err != nil {
			resp := goproxy.NewResponse(req, "text/plain", 500, fmt.Sprintf("Error: %#v\n", err))
			return nil, resp
		}
		//TODO: make sure at least on of these actions above has success
		if (cred == nil) {
			log.Fatal("cred should not be nil")
		}
		login(originalURL.Host, *cred)

		// embed the original site in an iframe in our management frame.

		originalURL.Scheme = "http" // send users follow up requests back to us
		var data = map[string]interface{} {
			"Hostname": originalURL.Host,
			"CN": cred.CN,
			"URL": originalURL.String(),
			"Comment": cred.Comment,
		}
		buf := execTemplate(templates, "embed.html", data)
		resp := makeResponse(req, 200, "text/html", buf)
		return nil, resp
	}
	log.Printf("Unexpected method: %#v", req.Method)
	return nil, nil
}


// Strip the portnumber from the net.URL.Host string to get the hostname
//var hostnameRE = regexp.MustCompile("^([^:]+):[0-9]+$")
var hostnameRE = regexp.MustCompile("^([^:]+)")

func getHostname(host string) (string) {
	hostname := getFirst(hostnameRE.FindStringSubmatch(host))
	if hostname == "" {
		panic("no hostname in " + host)
	}
	return hostname
}

// Strip the hostname and return the port from the hostname:port or IP-address:port
var portnrRE = regexp.MustCompile(":([0-9]+)$")

func getPort(address string) (string) {
	port := getFirst(portnrRE.FindStringSubmatch(address))
	if port == "" {
		panic("no port number in " + address)
	}
	return port
}

// Register the named accountname at the sites' CA. Uses a new private key.
func registerCN(hostname string, cn string, comment string) (*credentials, error) {
	log.Println("registering cn: ", cn, " for: ", hostname, " with comment: ", comment)

	priv, err := rsa.GenerateKey(CryptoRand.Reader, 1024)
	if err != nil {
		panic("cannot generate private key")
	}

	serverCred, exists := getServerCreds(hostname)
	if exists == false { panic("We don't have any server credentials for <hostname>") }
	regURL, err := url.Parse(registerURLmap[hostname])
	check(err)

	servername := getHostname(regURL.Host)

	tr := makeCertConfig(servername, serverCred.caCert)
	client := &http.Client{Transport: tr}

	cert, err := signupPubkey(client, regURL.String(), cn, priv.PublicKey)
	if err != nil { return nil, err }

	var privPEM  bytes.Buffer
	pem.Encode(&privPEM, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)})

	creds := credentials{
		Hostname: hostname,
		Realm: "",
		CN: cn,
		Cert: cert,
		Priv: privPEM.Bytes(),
		Created: time.Now().Unix(),
		LastUsed: time.Now().Unix(), // user is logged-in immedeatly
		Comment: comment,
	}
	// Register the data and set it as login certificate
	// It's what the user would expect from signup.
	setCredentials(creds)
	return &creds, nil
}


// Signup at the registerURL with the Public key and cn for username
// expect a 201-Created with a PEM certificate or
// a 403-forbidden when the cn is already in use
func signupPubkey(client *http.Client, registerURL string, cn string, pub rsa.PublicKey) ([]byte, error) {
	pubkey := publicKeyToPEM(pub)
	resp, err := client.PostForm(registerURL, url.Values{"cn": {cn}, "pubkey": {pubkey}})
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, errors.New("error reading response.body")
	}

	if resp.StatusCode == 403 {
		return nil, fmt.Errorf("Username '%s' is already taken. Please choose another", cn)
	}

	if resp.StatusCode == 201 {
		_ =  pemDecodeCertificate(body) // decode and panic if it fails to decode properly.
		return body, nil
	}

	log.Printf("SignPubKey got response: %#v\n", resp)

	return nil, errors.New(fmt.Sprintf("Some error happened: %s ", body))
}

//------------------ Manager
// show current logins and allow for logouts.

func handleManager (req *http.Request, ctx *goproxy.ProxyCtx) (*http.Request, *http.Response) {
	req.ParseForm()
	log.Printf("Form parameters are: %v\n", req.Form)

	switch req.Method {
	case "GET":
		details := getAllDetails()
		buf := execTemplate(templates, "showLogins.html", map[string]interface{}{
			"current":    logins,
			"alldetails": details,
		})
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


func handleDirectConnections(req *http.Request, ctx *goproxy.ProxyCtx) (*http.Request, *http.Response) {
        // Show received calls waiting for accept;
        // Show active calls;
        // Handle buttons to accept, reject and hang up calls.
	req.ParseForm()
	log.Printf("Form parameters are: %v\n", req.Form)
	log.Printf("callers_waiting is %v\n", callers_waiting)
	log.Printf("active_calls is %v\n", active_calls)
	switch req.Method {
	case "GET":
		buf  := execTemplate(templates, "directConnections.html", map[string]interface{}{
		    "callers": callers_waiting,
		    "active_calls": active_calls,
		})
		resp := makeResponse(req, 200, "text/html", buf)
		return nil, resp
	case "POST":
		id := req.Form.Get("id")
		accept := req.Form.Get("accept") != ""
		reject := req.Form.Get("reject") != ""
		hangup := req.Form.Get("hangup") != ""

		if id == "" {
		    log.Printf("Error: No <id> given. Reject request.\n")
		} else {

		    if accept || reject  {
		        caller, exists := callers_waiting[id]
		        if !exists {
		            // No such id
		            log.Printf("Error: Id not found in callers_waiting. Reject request.\n")
		        } else {

		            if accept {
                                // user wants to connect to caller
				log.Printf("Accepting call from %v\n", caller.UserCN)
			    	// move caller to active-callers
			    	delete(callers_waiting, id)
			    	active_calls[id] = caller
			    	// signal acceptance and get going
			    	_, _ = caller.Tlsconn.Write([]byte("call accepted\n"))
			    	go startPayload(id, caller.Tlsconn, caller.UserCN, caller.App)
		            }

			    if reject {
		                // user wants to refuse the connection
			    	delete(callers_waiting, id)
			    	_, _ = caller.Tlsconn.Write([]byte("call refused\n"))
			    	caller.Tlsconn.Close()
			    }
			}
		    }

		    if hangup {
		    	caller, exists := active_calls[id]
		        if !exists {
		            // No such id
		            log.Printf("Error: Id not found in active_call. Reject request.\n")
		        } else {
		            // user wants to hangup the connection
			    delete(active_calls, id)
			    caller.Tlsconn.Close()
			}
		    }
		}

		// redirect back to ourself to show the updated status in calls_waiting and active_calls
		resp := makeRedirect(req, req.URL)
		return nil, resp
	}

	log.Fatal("Unexpected method: ", req.Method)
	return nil, nil
}


func handleDialDirectConnection(req *http.Request, ctx *goproxy.ProxyCtx) (*http.Request, *http.Response) {
	// see who we're gonna call
	req.ParseForm()
	switch req.Method {
	case "POST":
		connectionID := req.Form.Get("connectionID")
		if connectionID == "" {
			log.Printf("Missing connectionID")
			return nil, goproxy.NewResponse(req,
				goproxy.ContentTypeText, http.StatusBadRequest,
				"Missing connectionID.")
		}
		log.Printf("handleDirectConnection has connectionID: %s", connectionID)

		invitation := getInvitation(connectionID)
		if invitation == nil {
			log.Printf("Wrong connectionID")
			return nil, goproxy.NewResponse(req,
				goproxy.ContentTypeText, http.StatusBadRequest,
				"Proxy has been restarted since this page was served. Please log in again.")
		}

		//log.Printf("invitation is: %#v", invitation)

		inviteeName, inviteeHost, err := eccentric.ParseCN(invitation.InviteeCN)
		check(err)
		log.Printf("invitee is: %v, %v", inviteeName, inviteeHost)

		// fetch our own identity
		ourCreds := getLoggedInCreds(inviteeHost)
		if ourCreds == nil {
			// should not happen, as we need to be logged in to get the dial-button, but anyway
			log.Println("Site says to dial a direct connection but you are not logged in.")
			return nil, goproxy.NewResponse(req,
				goproxy.ContentTypeText, http.StatusInternalServerError,
				"Ecca Proxy error: Site says to dial a direct connection but you haven't logged in. Please log in first, then try again.")
		}

		log.Printf("our creds are: %v\n", ourCreds.CN)
		ourCert, err := tls.X509KeyPair(ourCreds.Cert, ourCreds.Priv)
		check(err)
		//log.Printf("ourCert is: %#v", ourCert)

		// call out and show the response
		response := dialDirectConnection(invitation, ourCert)
		return nil, goproxy.NewResponse(req, goproxy.ContentTypeText, http.StatusOK, response)
	}

	log.Printf("Unexpected method: %#v", req.Method)
	return nil, nil
}


// dial the direct connection and start a conversation
func dialDirectConnection(invitation *DCInvitation, ourCert tls.Certificate) string {
	fpca, err := eccentric.ParseCertByteA(invitation.ListenerFPCAPEM)
	check(err)
	log.Printf("FPCA is %v", fpca.Subject.CommonName)

	pool := x509.NewCertPool()
	pool.AddCert(fpca)

	log.Printf("calling: %v at %v for %v", invitation.ListenerCN, invitation.Endpoint, invitation.Application)
	clientConfig := tls.Config{
		ServerName: invitation.ListenerCN,
		Certificates: []tls.Certificate{ourCert},
		RootCAs: pool,
	}
	// direct ip endpoint
	//conn , err := tls.Dial("tcp", invitation.Endpoint, &clientConfig)
	//check(err)

	// Connect to the onion endpoint
	socks := &socks4a.Socks4a {
		Network: "tcp",
		Address: *torSocksPort,
	}
	conn, err := socks.Dial(invitation.Endpoint)
	if err != nil {
		log.Printf("Error dialing endpoint: %#v; reason: %#v", invitation.Endpoint, err)
		return fmt.Sprintf("Error dialing endpoint: %#v; reason: %#v", invitation.Endpoint, err)
	}

	// start TLS over the onion connection
	tlsconn := tls.Client(conn, &clientConfig)
	err = tlsconn.Handshake()
	check(err)

	caller := makeCaller(tlsconn, invitation.ListenerCN, invitation.Application)
	callers_waiting[caller.Token] = caller
	go startPayload(caller.Token, tlsconn, invitation.ListenerCN, invitation.Application)
	return fmt.Sprintf("Starting application: %s.", invitation.Application)
}

// Start the requested application eg. chat/voice/video etc
func startPayload(id string, tlsconn *tls.Conn, remoteCN, app string){
	switch app {
	case "chat": startChatApp(id, tlsconn, remoteCN)
	case "voice": startVoiceApp(id, tlsconn, remoteCN)
	}
}

// Start the simple chat app on the encrypted channel.
func startChatApp(id string, tlsconn *tls.Conn, remoteCN string){
	// Create listener socket for the simple chat
	socket, err := net.Listen("tcp", "[::1]:0")
	check (err)
	port := getPort(socket.Addr().String())

	// start the chat app and point it to our socket
	cmd := exec.Command("uxterm", "-e", "nc", "-6", "::1", port)

	err = cmd.Start() // start asynchronously
	check(err)

	// wait for it to connect
	app, err := socket.Accept()
	check(err)

	// show a welcome message
	mess := fmt.Sprintf("Connected to %s, chat away!\n", remoteCN)
	app.Write([]byte(mess))
	app.Write([]byte(fmt.Sprintf("%s\n", strings.Repeat("-", len(mess) -1))))

	// copy the TLS-connection to the chat app and back
	go io.Copy(app, tlsconn)
	go io.Copy(tlsconn, app)

	// wait for it to finish
	err = cmd.Wait()
	check(err)

	// Close all, including the socket and the TLS channel.
	// We run this only once.
	app.Close()
	socket.Close()
	tlsconn.Close()
}

// Start the simple voice app on the encrypted channel.
func startVoiceApp(id string, tlsconn *tls.Conn, remoteCN string){
	// start the speaker part and connect it to our socket
	spr := exec.Command("/usr/bin/env", "aplay")
	spr.Stdin = tlsconn
	err := spr.Start() // start asynchronously
	check(err)

	// start the microphone too
	// defaults: 1 channel 8000 Hz sample rate, WAVE format
	mic := exec.Command("/usr/bin/env", "arecord", "--rate=8000")
	mic.Stdout = tlsconn
	err = mic.Start() // start asynchronously
	check(err)

	// wait for it to finish
	// User closes the Tlsconn socket, breaking the mic and spk processes.
	// Don't check for errors as that's guaranteed.
	_ = mic.Wait()
	_ = spr.Wait()

	delete(active_calls, id)
	tlsconn.Close()
}

// var handleInitiateDirectConnectionTemplate = template.Must(template.New("initiateDirectConnection").Parse(
// `<html>
// <body>
//  <h1>Creating a direct connection</h1>
//   <h3>Awaiting</h3>
//    <p>Activity log:
//    <ul>
//    <li>creating a listening port at {{ .port }}.</li>
//    <li>sent inviation to {{ .addressee }}.</li>
//    <li>awaiting connection...</li>
//    </ul></p>
//    <hr/>
//    <p>This listening port stays up until you close the Ecca-proxy. You can browse to other pages or site.
//       Don't worry closing this page, when the addresse connects you'll get a new window.</p>
//  </body>
// </html>`))



// func handleShowCert (req *http.Request, ctx *goproxy.ProxyCtx) (*http.Request, *http.Response) {
// 	cn := req.FormValue("cn")

// 	switch req.Method {
// 	case "GET":
// 		username, hostname, err := eccentric.ParseCN(cn)
// 		check(err)
//  		creds := getCred(hostname, username)
// // TODO: map the binary cred.Cert into a x509.Certificate
// 		certs := mapCredsToCerts(creds)
// 		buf  := execTemplate(showFullCertTemplate, "showFullCert", map[string]interface{}{
// 			"certs": certs,
// 		})
// 		resp := makeResponse(req, 200, "text/html", buf)
// 		log.Println("Show full certificate")
// 		return nil, resp
// 	}

// 	log.Fatal("Unexpected method: ", req.Method)
// 	return nil, nil
// }

// var showFullCertTemplate = template.Must(template.New("showFullCert").Parse(
// `<html>
// <body>
//  <h1>Manage your Eccentric Authentication logins</h1>
//  <h3><Full Certificate/h3>
//    <p>This is the certificate

//     <table>
//       <tr><th>Key</th><th>Value</th></tr>
//       {{range $cert := .certs }}
//          <tr> <td> CN </td> <td> {{ $cert.CN }}</td> </tr>
//     {{ else }}
//       <tr><td colspan="2">Wrong cn</td></tr>
//     {{ end }}
//     </table>
//  </body>
// </html>`))

// func mapCredsToCerts(cred *credentials) (certs []x509.Certificate) {
// 	if cred == nil { return }
// 	cert, err := eccentric.ParseCertByteA(cred.Cert)
// 	check(err)
// 	certs = append(certs, *cert)
// 	return
// }


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


func execTemplate(template *template.Template, name string, data map[string]interface{}) (*bytes.Buffer) {
	buf := new(bytes.Buffer)
	data["Page"] = name
	err := template.ExecuteTemplate(buf, name, data)
	if err != nil {
		log.Fatal("error executing template: ", err)
	}
	return buf
}
