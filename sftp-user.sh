#!/bin/bash

set -e

USER=${1?Need user}
ROOT=${2:-/var/www/vhosts}
PASSWORD=$(pwgen -s 31)
DBPW=$(pwgen -s 31)

mkdir -p $ROOT/$USER
useradd -d $ROOT/$USER -g www-data -G sftponly $USER
mkdir -p $ROOT/$USER/{htdocs,private}
chown $USER:www-data $ROOT/$USER/{htdocs,private}

dbname=$(tr . _ <<<${USER})
userid=${USER:0:15}

mysqladmin create "$dbname"
echo "GRANT ALL PRIVILEGES ON \`$dbname\`.* TO \`$userid\`@localhost IDENTIFIED BY '$DBPW';" | \
        mysql

cat > "/etc/nginx/sites-enabled/$USER.conf" <<END
server {
    server_name $1;
    root /var/www/$1;
    include /etc/nginx/php5-fpm;
    location / {
        index index.php;
        if (!-e \$request_filename) {
            rewrite ^(.*)$  /index.php last;
        }
    }
}
END

echo "$USER:$PASSWORD" | chpasswd
echo "$USER@$(hostname):$PASSWORD:$userid:$DBPW:$dbname"
