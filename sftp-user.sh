#!/bin/bash

set -e

SITE=${1?Need user}
USER=$(awk -F. '{print$1}' <<<$SITE)
ROOT=${2:-/var/www/vhosts}
PASSWORD=$(pwgen -s 31)
DBPW=$(pwgen -s 31)

mkdir -p $ROOT/$USER
useradd -d $ROOT/$USER -g www-data -G sftponly -s /bin/false $USER
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
        index index.php;

        location ~ \.php$ {
                include /etc/nginx/fastcgi_params;

                fastcgi_index index.php;
                fastcgi_param SCRIPT_FILENAME \$document_root\$fastcgi_script_name;
                if (-f \$request_filename) {
                        fastcgi_pass unix:/var/run/php5-fpm.$USER.sock;
                }
        }

        location / {
                try_files \$uri \$uri/ /index.php;
        }
}

#server {
#       listen 443 ssl;
#       listen [::]:443 ssl;
#
#       server_name $SITE;
#       root /var/www/vhosts/$USER/htdocs;
#
#       add_header Strict-Transport-Security “max-age=31536000; includeSubdomains”;
#
#       ssl_certificate /etc/ssl/crt/$(date +%Y)-$SITE.crt;
#       ssl_certificate_key /etc/ssl/private/$(date +%Y)-$SITE.key;
#
#       include /etc/nginx/php5-fpm;
#       index index.php;
#
#       location ~ \.php$ {
#               include /etc/nginx/fastcgi_params;
#
#               fastcgi_index index.php;
#               fastcgi_param SCRIPT_FILENAME \$document_root\$fastcgi_script_name;
#               if (-f \$request_filename) {
#`                       fastcgi_pass unix:/var/run/php5-fpm.$USER.sock;
#               }
#       }
#       location / {
#               try_files \$uri \$uri/ /index.php;
#       }
#}
END

cat > "/etc/php5/fpm/pool.d/$USER.conf" <<END
[$USER]
user = $USER
group = www-data
listen = /var/run/php5-fpm.$USER.sock
pm = dynamic
pm.max_children = 5
pm.start_servers = 2
pm.min_spare_servers = 1
pm.max_spare_servers = 3
chdir = /
END

echo "$USER:$PASSWORD" | chpasswd

# username : pampassword : mysql username : mysql password : mysql database
echo "$USER@$(hostname):$PASSWORD:$userid:$DBPW:$dbname" | tee -a .sftpuserinfo

service php5-fpm reload

ln -s ../sites-available/$USER /etc/nginx/sites-enabled
nginx -tq && service nginx reload
