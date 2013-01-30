ecca-proxy
==========

A web proxy server that transparantly handles the Eccentric Authentication key and 
certificate management, making client side certificates easy.

Eccentric Authentication is a protocol designed to make using client certificates 
easy, secure and private. Easier than using passwords over the internet. Secure 
because of the Public and Private keys and certificates that we know for 20 years. 
Private because you decide when to log in with a certificate or not. And you can 
create as many certificates for a single site as you wish. Good bye user tracking.

This repository contains a web proxy service to handle all the difficult cryptographic
details and provides an easy to use interface to the user.

