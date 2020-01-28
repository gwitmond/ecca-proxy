## Installation of the Ecca-Proxy User Agent from source

# prefab

There is a (old) prefab 64-bit binary for Debian 7.0 (Wheezy and later) at my [blog](http://eccentric-authentication.org/blog/2013/06/07/run-it-yourself). 

# build it yourself

## user setup  

(optional: if you want to keep *my* code out of *your* home directory)

    useradd -m -U eccaproxy
    usermod -p 'no-password-login' eccaproxy
    passwd -u eccaproxy
    sudo -H -u eccaproxy -s

## basic setup

    mkdir -p ~/gopath/src
    export GOPATH=~/gopath
    echo !! >> ~/.bashrc

## Go language build requirements

    sudo apt-get install golang git make

## ecca-proxy specific requirements

    sudo apt-get install libunbound-dev libssl-dev tor

## add user to group tor

    sudo usermod -a -G debian-tor $USER

log out and in to effectuate it
    
## build it

    cd ~/gopath/src
    go get -v github.com/gwitmond/ecca-proxy
    cd ~/gopath/src/github.com/gwitmond/ecca-proxy
    make

it should build without errors with go-1.8 or higher

# Configure Tor

create a password and edit /etc/tor/torrc

    secret=`tor --quiet --hash-password 'geheim'`
    sudo sed -i -e 's/^#*ControlPort.*$/ControlPort 9051/'                           /etc/tor/torrc
    sudo sed -i -e "s/^#*HashedControlPassword\.\*\$/HashedControlPassword $secret/" /etc/tor/torrc
    /etc/init.d/tor restart

# Run it

    $ ./ecca-proxy -torcontrolpassword 'geheim'

It listens on localhost port 8000, either IPv4 and IPv6.

## Use it

    $ firefox -noremote -ProfileManager

Create a new profile if you don't want to mess up your current one.
Configure you browser to use localhost port 8000 as http-proxy.

    Browse to: http://dating.wtmnd.nl/
    or 	   to: http://cryptoblog.wtmnd.nl/
    
Notice: as the proxy takes care of all cryptographic details, point your browser to http (not https).

