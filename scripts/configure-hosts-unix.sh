#!/bin/bash

site_name="$1"
localhost_ip="127.0.0.1"

sudo -- sh -c -e "echo '$localhost_ip   $site_name\n$localhost_ip   ws.$site_name' >> /etc/hosts"
