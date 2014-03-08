#!/bin/bash

set -e

SITE=${1?Need user}
USER=$(awk -F. '{print$1}' <<<$SITE)
ROOT=${2:-/var/www/vhosts}
PASSWORD=$(pwgen -s 31)
DBPW=$(pwgen -s 31)

mkdir -p $ROOT/$USER
useradd -d $ROOT/$USER -g www-data -G sftponly-s /bin/false $USER
mkdir -p $ROOT/$USER/{htdocs,private}
chown $USER:www-data $ROOT/$USER/{htdocs,private}

dbname=$(echo $USER | tr . _)
userid=${USER:0:15}

mysqladmin create "$dbname"
echo "GRANT ALL PRIVILEGES ON \`$dbname\`.* TO \`$userid\`@localhost IDENTIFIED BY '$DBPW';" | \
        mysql

cat > "/etc/nginx/sites-available/$USER" <<END
server {
        server_name $SITE;
        root /var/www/vhosts/$USER/htdocs;

        include /etc/nginx/php5-fpm;
        location / {
                index index.php;
                if (!-e \$request_filename) {
                        rewrite ^(.*)$  /index.php last;
                }
        }
}

#server {
#       listen 443 ssl;
#       listen [::]:443 ssl;
#
#       server_name $SITE;
#       root /var/www/vhosts/$USER/htdocs;
#
#       ssl_certificate /etc/ssl/crt/$(date +%Y)-$SITE.crt;
#       ssl_certificate_key /etc/ssl/private/$(date +%Y)-$SITE.key;
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
