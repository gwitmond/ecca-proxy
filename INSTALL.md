## Installation of the Ecca-Proxy User Agent

## user setup 

useradd -m -U eccaproxy
usermod -p 'no-password-login' eccaproxy
passwd -u eccaproxy
sudo -H -u eccaproxy -s  

## basic setup

mkdir -p ~/gopath/src
export GOPATH=~/gopath
echo '!!' >> ~/.bashrc

## Go language requirements
sudo apt-get install golang gcc git


## ecca-proxy specific requirements
sudo apt-get install libsqlite3-dev sqlite3 libunbound-dev libssl-dev

cd gopath/src
go get github.com/gwitmond/ecca-proxy
# it should build without errors


## Run it
$ cd ~gopath/src/gwitmond/ecca-proxy
$ ./ecca-proxy

It listens on localhost port 8000.

## Use it

$ firefox -noremote -ProfileManager

#Create a new profile if you don't want to mess up your current one.
#Configure you browser to use localhost port 8000 as http-proxy.
#check with netstat -an|grep 8000 to see if it is ipv4 or ipv6.

Browse to: http://dating.wtmnd.nl:10443/

Notice: as the proxy takes care of all cryptographic details, point your browser to http (not https).
