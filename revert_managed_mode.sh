#!/bin/bash

if [ "$#" -ne 2 ]; then
    echo "Usage: $0 <interface> <channel>"
    exit 1
fi

interface=$1
channel=$2

sudo ip link set $interface down
sudo iwconfig $interface channel $channel
sudo iwconfig $interface mode managed
sudo ip link set $interface up

echo "Managed mode enabled for interface $interface on channel $channel"
iwconfig $interface