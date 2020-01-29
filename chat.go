// Ecca Authentication Proxy
//
// Handles Eccentric Authentication in a web proxy for browsers.
//
// Copyright 2020, Guido Witmond <guido@witmond.nl>
// Licensed under AGPL v3 or later. See LICENSE

package main // eccaproxy

import (
	"github.com/elazarl/goproxy"
	"log"
	"bytes"
	"net/http"
	"net/url"
	"io"
	"crypto/tls"
	"encoding/json"
	"time"
	"strconv"
)

// received messages are tagged with the token of the connection
type message struct {
     Token string
     Sender string
     Message string
}

var chatChan   = make(chan message, 100)

// Chat page polls here for messages
// listen on the chatChan for newly received messages and hand them to the front end.
func handleChatpoll (req *http.Request, ctx *goproxy.ProxyCtx) (*http.Request, *http.Response) {
    timeout, err := strconv.Atoi(req.URL.Query().Get("timeout"))
    if err != nil || timeout > 180000 || timeout <= 1000 {
        timeout = 60000; // milliseconds
    }

    // Timeout before the client does.
    // It compensates for transmission delays
    // and prevents races where we send a reply just after the client has timed out.
    // That would cause the client to miss an event.
    timeout = int(0.95 * float32(timeout))

    switch req.Method {
    case "GET":
	select {
    	case message := <- chatChan:
	    log.Printf("pushing message %v", message)
	    json, err := json.Marshal(message)
	    check(err)
	    resp := makeResponse(req, 200, "application/json", bytes.NewBuffer(json))
            return nil, resp
    	case <- time.After(time.Duration(timeout) * time.Millisecond):
            resp := makeResponse(req, 404, "text/plain", bytes.NewBuffer([]byte("timeout")))
            return nil, resp
    	}
    }

    log.Printf("Unexpected method: %#v", req.Method)
    time.Sleep(time.Second);
    return nil, nil
}


func startWebChatApp(req *http.Request, ctx *goproxy.ProxyCtx, token string, tlsconn *tls.Conn, remoteCN string)  (*http.Request, *http.Response) {
        // Start a receiver to listen for messages over the tls connection
	go chatReceiver(token, tlsconn, remoteCN, chatChan)
	
	// redirect the user to the chat page, on the current host and scheme.
	reqUrl := req.URL
	redirectURL := url.URL{Scheme: reqUrl.Scheme, Host: reqUrl.Host, Path: "/chat"}
	resp := makeRedirect(req, &redirectURL)
	return nil, resp
}


// listen on the tlsConnetion and send all incoming messages to the chat-channel
// tag each message with the token.
func chatReceiver(token string, tlsconn *tls.Conn, remoteCN string, channel chan message) {
        buffer := make([]byte, 1000)
	stop := false
    	for !stop {
	    	log.Printf("receiver waiting for tlsconn")
                size, err := tlsconn.Read(buffer)
		log.Printf("receiver received %v bytes", size)
        	switch err {
		case io.EOF: 
	    	    stop = true
		case nil:
	    	    channel <- message{token, remoteCN, string(buffer[:size])}
        	}
    	}
	// tls connection said EOF (or some other error), close it.
	tlsconn.Close()
	delete(active_calls, token)
}


// Users post their messages here for delivery to the other side
// Upon sending, copy into the chatChan for reflection
func handleChatPostPath (req *http.Request, ctx *goproxy.ProxyCtx) (*http.Request, *http.Response) {
    //log.Printf("ChatPost has req: %#v", req)
    switch req.Method {
    case "POST":
    	req.ParseForm()
        token :=   req.Form.Get("token")
	messageText := req.Form.Get("message")

	if token == "" {
	        log.Printf("Error: No <token> given. Reject request.\n")
		return nil, nil   // TODO: improve error reporting
	}

	// test for active chat
	caller, exists := active_calls[token]
	if !exists {
	        log.Printf("Error: token not found. Reject request.\n")
		return nil, nil   // TODO: improve error reporting
	}

	size, err := caller.Tlsconn.Write([]byte(messageText))
	switch err {
	case nil: 	    // send ok
	    log.Printf("send successful")
	    chatChan <- message{token, "Me", messageText}
    	    resp := makeResponse(req, 200, "application/json", bytes.NewBuffer([]byte("[]")))
            return nil, resp
	default:            // some error happened
	    log.Printf("ChatPost got error: %v")
	    log.Printf("%v of %v bytes did get sent", size, len(messageText))
	    caller.Tlsconn.Close()
	    delete(active_calls, token)
	    resp := makeResponse(req, 500, "application/json", bytes.NewBuffer([]byte("[]")))
            return nil, resp
        }
    }
    log.Printf("Unexpected method: %#v", req.Method)
    time.Sleep(time.Second);
    return nil, nil
}


// Create the /chat page.
// Populate it with a section for each active chat.
func handleChat(req *http.Request, ctx *goproxy.ProxyCtx) (*http.Request, *http.Response) {
	// collect the tokens for accepted chats.
	tokens := []string{}
	for token, caller := range active_calls {
	    if caller.App == "chat" {
	        tokens = append(tokens, token)
	    }
	}

	buf := execTemplate(templates, "chat.html", map[string]interface{} { "tokens": tokens })
	resp := makeResponse(req, 200, "text/html", buf)
	return nil, resp
}

