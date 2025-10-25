#!/bin/bash

if [ "$#" -ne 2 ]; then
    echo "Usage: $0 <interface> <channel>"
    exit 1
fi

interface=$1
channel=$2

sudo systemctl stop NetworkManager
sudo systemctl stop wpa_supplicant

sudo ip link set $interface down
sudo iw dev $interface set channel $channel
sudo iw dev $interface set type managed
sudo ip link set $interface up

echo "Monitor mode enabled for interface $interface on channel $channel"
iwconfig