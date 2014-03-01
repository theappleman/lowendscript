#!/bin/bash

USER=${1?Need user}

set -e

mkdir -p /var/www/$USER

useradd -d /var/www/$USER -g www-data -G sftponly $USER
passwd $USER
