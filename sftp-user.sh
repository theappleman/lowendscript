#!/bin/bash

USER=${1?Need user}
ROOT=${2:-/var/www/vhosts}

set -e

mkdir -p $ROOT/$USER

useradd -d $ROOT/$USER -g www-data -G sftponly $USER

mkdir -p $ROOT/$USER/{htdocs,private}
chown $USER:www-data $ROOT/$USER/{htdocs,private}

PASSWORD=$(pwgen -s 31)

echo "$USER:$PASSWORD" | chpasswd
echo "$USER@$(hostname):$PASSWORD"
