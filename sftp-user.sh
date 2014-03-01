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
        listen 0.0.0.0:80;
        listen [::]:80;

        server_name $USER;
        root /var/www/$USER/htdocs;

        include /etc/nginx/php5-fpm;
        location / {
                index index.php;
                if (!-e \$request_filename) {
                        rewrite ^(.*)$  /index.php last;
                }
        }
}

#server {
#       listen 0.0.0.0:443 ssl;
#       listen [::]:443 ssl;
#
#       server_name $USER;
#       root /var/www/$USER/htdocs;
#
#       ssl_certificate /etc/nginx/ssl/$(date +%Y)-$USER.crt;
#       ssl_certificate_key /etc/nginx/ssl/$(date +%Y)-$USER.key;
#
#       include /etc/nginx/php5-fpm;
#       location / {
#               index index.php;
#               if (!-e \$request_filename) {
#                       rewrite ^(.*)$  /index.php last;
#               }
#       }
#}
END

echo "$USER:$PASSWORD" | chpasswd

# username : pampassword : mysql username : mysql password : mysql database
echo "$USER@$(hostname):$PASSWORD:$userid:$DBPW:$dbname" | tee -a .sftpuserinfo
