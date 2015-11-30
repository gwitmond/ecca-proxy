#!/bin/sh

usage() {
    echo "Usage: sudo $0 <username>"
    echo
    echo "Add <username> to the group 'debian-tor'"
    echo "It's needed to create Tor hidden services so others can reach you."
    echo "Otherwise you can only dial to hidden services of others."
    exit 1
}

# test for root
[ `id -nu` != 'root' ] && usage

# test for username
[ $# ne 1 ] && usage

# we're root and have a username, go ahead. 
usermod -a -G debian-tor $1

echo "User $1 has been added to group 'debian-tor'"
echo "Log out and log in again as user $1 to effect the change"