#!/bin/bash

set -e

function add_6addr {
	check_install ip iproute
	ADDR=$1

	if ! (/sbin/ip -6 a | grep -q $ADDR); then
		ip -6 addr add $ADDR dev eth0
		tee -a /etc/network/interfaces <<<"     up ip -6 addr add $ADDR dev eth0"
	fi
}

function check_install {
	if [ -z "`which "$1" 2>/dev/null`" ]
	then
		executable=$1
		shift
		while [ -n "$1" ]
		do
			DEBIAN_FRONTEND=noninteractive apt-get -q -y install "$1"
			print_info "$1 installed for $executable"
			shift
		done
	else
		print_warn "$2 already installed"
	fi
}

function check_install_testing {
	repo_testing
	if [ -z "`which "$1" 2>/dev/null`" ]
	then
		executable=$1
		shift
		while [ -n "$1" ]
		do
			DEBIAN_FRONTEND=noninteractive apt-get -t testing -q -y install "$1"
			print_info "$1 installed for $executable"
			shift
		done
	else
		print_warn "$2 already installed"
	fi
}

function check_remove {
	if [ -n "`which "$1" 2>/dev/null`" ]
	then
		DEBIAN_FRONTEND=noninteractive apt-get -q -y remove --purge "$2"
		print_info "$2 removed"
	else
		print_warn "$2 is not installed"
	fi
}

function check_sanity {
	# Do some sanity checking.
	if [ $(/usr/bin/id -u) != "0" ]
	then
		die 'Must be run by root user'
	fi

	if [ ! -f /etc/debian_version ]
	then
		die "Distribution is not supported"
	fi

	test -x "$0" || chmod +x "$0"
}

function die {
	echo "ERROR: $1" > /dev/null 1>&2
	exit 1
}

function get_domain_name() {
	# Getting rid of the lowest part.
	domain=${1%.*}
	lowest=`expr "$domain" : '.*\.\([a-z][a-z]*\)'`
	case "$lowest" in
	com|net|org|gov|edu|co)
		domain=${domain%.*}
		;;
	esac
	lowest=`expr "$domain" : '.*\.\([a-z][a-z]*\)'`
	[ -z "$lowest" ] && echo "$domain" || echo "$lowest"
}

function get_password {
	check_install pwgen pwgen 2>&1 >/dev/null
	KEY=$1
	PASSWORD=$(pwgen -s 31 1)

	if test "$(which redis-cli 2>/dev/null)"; then
		RDPASS=$(redis-cli get $KEY | cut -d\" -f2)
		if test x"$RDPASS" = "x"; then
			redis-cli set "$KEY" "$PASSWORD" 2>&1 >/dev/null
			redis-cli sadd nodes "$KEY" 2>&1 >/dev/null
			echo "$PASSWORD"
		else
			echo "$RDPASS"
		fi
	else
		if grep -q "$KEY" .userinfo 2>/dev/null; then
			grep "$KEY" .userinfo | cut -d= -f2
		else
			cat >> .userinfo <<<"$KEY=$PASSWORD"
			echo "$PASSWORD"
		fi
	fi
}

function install_dash {
	check_install dash dash
	rm -f /bin/sh
	ln -s dash /bin/sh
}

function install_dovecot {
	check_install doveconf dovecot-imapd
}

function install_munin {
	check_install munin-node munin-node libcache-cache-perl
	if test "$(which mysqladmin 2>/dev/null)" && \
		test x"$(mysqladmin ping)" = "xmysqld is alive" && \
		test ! -f /etc/munin/plugin-conf.d/mysql; then
		muninpass=$(get_password mysql:munin)
		mysql -e "CREATE USER 'munin'@'localhost' IDENTIFIED BY '$muninpass';"
		mysql -e "GRANT PROCESS,SUPER ON *.* TO 'munin'@'localhost';"
		mysql -e "GRANT SELECT ON mysql.* TO 'munin'@'localhost';"
		mysql -e "FLUSH PRIVILEGES;"

		cat >/etc/munin/plugin-conf.d/mysql <<EOF
[mysql*]
env.mysqladmin /usr/bin/mysqladmin --socket=/var/run/mysqld/mysqld.sock
env.mysqlopts --socket=/var/run/mysqld/mysqld.sock -umunin-p$muninpass
env.mysqluser munin
env.mysqlpassword $muninpass
EOF

		for i in $(/usr/share/munin/plugins/mysql_ suggest); do
			ln -s /usr/share/munin/plugins/mysql_ /etc/munin/plugins/mysql_$i
		done

		invoke-rc.d munin-node restart
	fi
}

function install_mysql {
	# Install the MySQL packages
	check_install mysqld mysql-server
	check_install mysql  mysql-client

	# Install a low-end copy of the my.cnf, and then delete
	# all the related files.
	invoke-rc.d mysql stop
	rm -f /var/lib/mysql/ib*
	cat > /etc/mysql/conf.d/lowendbox.cnf <<END
[mysqld]
key_buffer_size = 256K
query_cache_size = 0
default_storage_engine = MyISAM
max_connections = 20
max_user_connections = 10
innodb_buffer_pool_size=5M
END
	invoke-rc.d mysql start

	# Generating a new password for the root user.
	passwd=`get_password mysql:root`
	mysqladmin password "$passwd"
	cat > ~/.my.cnf <<END
[client]
user = root
password = $passwd
END
	chmod 600 ~/.my.cnf

	mysql -e "select user,host from mysql.user where password ='';" | \
		awk 'NR >1 { print "DROP USER `"$1"`@`"$2"`;" }' | \
		mysql
}

function install_nginx {
	check_install nginx nginx

	# Need to increase the bucket size for Debian 5.
	cat > /etc/nginx/conf.d/lowendbox.conf <<END
server_names_hash_bucket_size 64;
server_tokens off;
END

	invoke-rc.d nginx restart
}

function install_php {
	check_install php5-fpm php5-fpm php5-mysql
}

function install_polipo {
	check_install polipo polipo
	cat > /etc/polipo/config <<END
diskCacheRoot = ""
chunkHighMark = 819200
objectHighMark = 128
censoredHeaders = set-cookie, cookie, cookie2, from, accept-language
censorReferer = true
END
	invoke-rc.d polipo restart
}

function install_syslogd {
	# We just need a simple vanilla syslogd. Also there is no need to log to
	# so many files (waste of fd). Just dump them into
	# /var/log/(cron/mail/messages)
	check_install /usr/sbin/syslogd inetutils-syslogd
	invoke-rc.d inetutils-syslogd stop

	for file in /var/log/*.log /var/log/mail.* /var/log/debug /var/log/syslog
	do
		[ -f "$file" ] && rm -f "$file"
	done
	for dir in fsck news
	do
		[ -d "/var/log/$dir" ] && rm -rf "/var/log/$dir"
	done

	cat > /etc/syslog.conf <<END
*.*;mail.none;cron.none	-/var/log/messages
cron.*				-/var/log/cron
mail.*				-/var/log/mail
END

	[ -d /etc/logrotate.d ] || mkdir -p /etc/logrotate.d
	cat > /etc/logrotate.d/inetutils-syslogd <<END
/var/log/cron
/var/log/mail
/var/log/messages {
	rotate 4
	weekly
	missingok
	notifempty
	compress
	sharedscripts
	postrotate
		/etc/init.d/inetutils-syslogd reload >/dev/null
	endscript
}
END

	invoke-rc.d inetutils-syslogd start
}

function install_wordpress {
	check_install wget wget
	check_install rsync rsync

	SITE=$1
	USER=$(cut -d. -f1 <<<$SITE)
	dbname=$(tr . _<<<$SITE)
	userid=${SITE:0:15}

	# Downloading the WordPress' latest and greatest distribution.
	mkdir /tmp/wordpress.$$
	wget -O - http://wordpress.org/latest.tar.gz | \
		tar zxf - -C /tmp/wordpress.$$
	rsync -r /tmp/wordpress.$$/wordpress/ "/var/www/vhosts/$SITE/htdocs"
	rm -rf /tmp/wordpress.$$

	# Setting up the MySQL database
	passwd=$(get_password "mysql:$dbname")
	cp "/var/www/vhosts/$SITE/htdocs/wp-config-sample.php" "/var/www/vhosts/$SITE/htdocs/wp-config.php"
	sed -i "s/database_name_here/$dbname/; s/username_here/$userid/; s/password_here/$passwd/" \
		"/var/www/vhosts/$SITE/htdocs/wp-config.php"
	chown -R $USER:www-data /var/www/vhosts/$SITE/htdocs
	print_info "Wordpress site ($SITE) installed"
}

function install_interactive {
	check_install htop htop
	check_install strace strace
	check_install vim vim
	check_install git git
	check_install ncdu ncdu

	check_install nmap nmap
	check_install tcpdump tcpdump
	check_install telnet telnet
	check_install curl curl
	check_install dig dnsutils
}

function install_redis {
	check_install redis-server redis-server
	sed -i -e '/^appendonly.*$/s/.*/appendonly yes/' /etc/redis/redis.conf
	invoke-rc.d redis-server restart
}

function config_sshd {
	grep -q sftponly /etc/group || groupadd sftponly

	cat > /etc/ssh/sshd_config <<EOF
AllowGroups root users sftponly
Ciphers aes256-ctr,aes192-ctr,aes128-ctr
LogLevel FATAL
MACs hmac-sha1,hmac-ripemd160
PasswordAuthentication no
PermitRootLogin without-password
Subsystem sftp internal-sftp
UsePAM yes

Match Group users
	PasswordAuthentication yes

Match Group sftponly
	ChrootDirectory %h
	ForceCommand internal-sftp
	PasswordAuthentication yes
EOF

	invoke-rc.d ssh restart
}

function create_user {
	USER=$1
	PASSWORD=$(get_password user:$USER)
	useradd -m -G users -s /bin/bash $USER
	echo "$USER:$PASSWORD" | chpasswd
	print_info "user:$USER:$PASSWORD"
}

function create_mail {
	USER=$1
	PASSWORD=$(get_password mail:$USER)
	useradd -G mail -s /bin/false $USER
	echo "$USER:$PASSWORD" | chpasswd
	print_info "mail:$USER:$PASSWORD"
}

function create_sftp {
	SITE=$1
	USER=$(cut -d. -f1 <<<$SITE)
	PASSWORD=$(get_password sftp:$USER)
	mkdir -p /var/www/vhosts/$SITE/{.ssh,conf,htdocs,private}
	useradd -d /var/www/vhosts/$SITE \
		-g www-data -G sftponly -s /bin/false $USER
	chown $USER:www-data /var/www/vhosts/$SITE/{.ssh,conf,htdocs,private}
	echo "$USER:$PASSWORD" | chpasswd
	print_info "sftp:$USER:$PASSWORD"
}

function create_shell {
	SITE=$1
	USER=$(cut -d. -f1 <<<$SITE)
	PASSWORD=$(get_password shell:$USER)
	useradd -m -d /var/www/vhosts/$SITE \
		-G users -s /bin/bash $USER
	echo "$USER:$PASSWORD" | chpasswd
	print_info "shell:$USER:$PASSWORD"
}

function create_mysql {
	SITE=$1
	dbname=$(echo $SITE | tr . _)
	userid=${SITE:0:15}
	DBPW=$(get_password mysql:$dbname)

	mysqladmin create "$dbname"
	mysql -e "GRANT ALL PRIVILEGES ON \`$dbname\`.* TO \`$userid\`@localhost IDENTIFIED BY '$DBPW';"
	mysql -e "FLUSH PRIVILEGES;"
	print_info "mysql:$dbname:$DBPW:$userid"
}

function create_vhost {
	SITE=$1
	USER=$(cut -d. -f1 <<<$SITE)

	cat > "/etc/nginx/sites-available/$USER" <<END
server {
	server_name $SITE;
	root /var/www/vhosts/$SITE/htdocs;

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

#	rewrite ^(.*)$ https://\$server_name\$1 permanent;
}

#server {
#	listen 443 ssl;
#	listen [::]:443 ssl;
#
#	server_name $SITE;
#	root /var/www/vhosts/$USER/htdocs;
#
#	add_header Strict-Transport-Security “max-age=31536000; includeSubdomains”;
#
#	ssl_certificate /etc/ssl/crt/$(date +%Y)-$SITE.crt;
#	ssl_certificate_key /etc/ssl/private/$(date +%Y)-$SITE.key;
#
#	index index.php;
#
#	location ~ \.php$ {
#		include /etc/nginx/fastcgi_params;
#
#		fastcgi_index index.php;
#		fastcgi_param SCRIPT_FILENAME \$document_root\$fastcgi_script_name;
#		if (-f \$request_filename) {
#			fastcgi_pass unix:/var/run/php5-fpm.$USER.sock;
#		}
#	}
#	location / {
#		try_files \$uri \$uri/ /index.php;
#	}
#}
END

	ln -s ../sites-available/$USER /etc/nginx/sites-enabled
	nginx -tq && invoke-rc.d nginx reload
}

function create_vproxy {
	SITE=$1
	PORT=$2
	USER=$(cut -d. -f1 <<<$SITE)

	cat > "/etc/nginx/sites-available/$USER" <<END
upstream $USER {
        server 127.0.0.1:$PORT;
}

server {
	server_name $SITE;

        location / {
                proxy_pass      http://$USER;
        }
#	rewrite ^(.*)$ https://\$server_name\$1 permanent;
}

#server {
#	listen 443 ssl;
#	listen [::]:443 ssl;
#
#	server_name $SITE;
#
#	add_header Strict-Transport-Security “max-age=31536000; includeSubdomains”;
#
#	ssl_certificate /etc/ssl/crt/$(date +%Y)-$SITE.crt;
#	ssl_certificate_key /etc/ssl/private/$(date +%Y)-$SITE.key;
#
#	location / {
#                proxy_pass      http://$USER;
#        }
#}
END

	ln -s ../sites-available/$USER /etc/nginx/sites-enabled
	nginx -tq && invoke-rc.d nginx reload
}

function create_pool {
	SITE=$1
	USER=$(cut -d. -f1 <<<$SITE)

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

	invoke-rc.d php5-fpm reload
}

function print_info {
	echo -n -e '\e[1;36m'
	echo -n $1
	echo -e '\e[0m'
}

function print_warn {
	echo -n -e '\e[1;33m'
	echo -n $1
	echo -e '\e[0m'
}

function remove_unneeded {
	# Some Debian have portmap installed. We don't need that.
	check_remove /sbin/portmap portmap

	# Remove rsyslogd, which allocates ~30MB privvmpages on an OpenVZ system,
	# which might make some low-end VPS inoperatable. We will do this even
	# before running apt-get update.
	check_remove /usr/sbin/rsyslogd rsyslog

	# Other packages that seem to be pretty common in standard OpenVZ
	# templates.
	check_remove /usr/sbin/apache2 'apache2*'
	check_remove /usr/sbin/named bind9
	check_remove /usr/sbin/smbd 'samba*'
	check_remove /usr/sbin/nscd nscd

	# Need to stop sendmail as removing the package does not seem to stop it.
	if [ -f /usr/lib/sm.bin/smtpd ]
	then
		invoke-rc.d sendmail stop
		check_remove /usr/lib/sm.bin/smtpd 'sendmail*'
	fi
}

function update_upgrade {
	# Run through the apt-get update/upgrade first. This should be done before
	# we try to install any package
	apt-get -q -y update
	apt-get -q -y upgrade
}

function unattended_upgrades {
	check_install unattended-upgrades unattended-upgrades
	cat > /etc/apt/apt.conf.d/20auto-upgrades <<EOF
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade   "1";
EOF
}

function repo_testing {
	if test ! -f /etc/apt/sources.list.d/testing.list || \
		test ! -f  /etc/apt/preferences.d/20testing-pin; then
		cat > /etc/apt/sources.list.d/testing.list <<EOF
deb http://ftp.us.debian.org/debian testing main contrib non-free
EOF

		cat > /etc/apt/preferences.d/20testing-pin <<EOF
Package: *
Pin: release a=testing
Pin-Priority: -10

Package: opensmtpd
Pin: release a=testing
Pin-Priority: 10
EOF

		apt-get -q -y update
	fi
}

function install_opensmtpd {
	check_install_testing smtpd opensmtpd

	sed -i -e '/listen/s/localhost/eth0/' /etc/smtpd.conf

	invoke-rc.d opensmtpd restart
}

function make_admin {
	USER=$1
	gpasswd -a $USER adm
	gpasswd -a $USER sudo
}

function show_help {
	echo 'Usage:' `basename $0` '[option]'
	echo 'Available options:'
	for option in all alt system dovecot interactive ip mail mysql nginx php polipo redis user admin vhost wordpress '(npm)' '(opensmtpd)'
	do
		echo '  -' $option
	done
}

########################################################################
# START OF PROGRAM
########################################################################
export PATH=/bin:/usr/bin:/sbin:/usr/sbin

check_sanity

test "$#" = 0 && show_help
while test "$#" -gt 0; do
	case "$1" in
	admin)
		[ -z "$2" ] && die "Usage: `basename $0` $1 <user>"
		make_admin $2
		shift
		;;
	all)
		/bin/bash "$0" system int dovecot nginx munin php polipo
		;;
	alt)
		check_install nodejs nodejs
		check_install go golang
		check_install mojo libmojolicious-perl
		check_install perlbrew perlbrew liblocal-lib-perl
		;;
	dovecot)
		install_dovecot
		;;
	int*)
		install_interactive
		;;
	ip)
		[ -z "$2" ] && die "Usage: `basename $0` $1 <address/cidr>"
		add_6addr
		shift
		;;
	munin)
		install_munin
		;;
	mysql)
		install_mysql
		;;
	npm)
		check_install_testing npm npm
		;;
	nginx)
		install_nginx
		;;
	opensmtpd)
		install_opensmtpd
		;;
	php)
		install_php
		;;
	polipo)
		install_polipo
		;;
	system)
		remove_unneeded
		update_upgrade
		unattended_upgrades
		install_dash
		install_syslogd
		config_sshd
		;;
	wordpress)
		[ -z "$2" ] && die "Usage: `basename $0` $1 <name>"
		/bin/bash "$0" vhost $2
		install_wordpress $2
		shift
		;;
	redis)
		install_redis
		;;
	mail)
		[ -z "$2" ] && die "Usage: `basename $0` $1 <name>"
		create_mail $2
		shift
		;;
	user)
		[ -z "$2" ] && die "Usage: `basename $0` $1 <name>"
		create_user $2
		shift
		;;
	vhost)
		[ -z "$2" ] && die "Usage: `basename $0` $1 <name>"
		create_sftp $2
		create_vhost $2
		create_mysql $2
		create_pool $2
		shift
		;;
	shell)
		[ -z "$2" ] && die "Usage: `basename $0` $1 <name>"
		port=$(perl -e 'print int(rand(65535-1023))+1024')
		create_shell $2
		create_vproxy $2 $port
		create_mysql $2
		print_info "HTTP Proxy port: $port"
		shift
		;;
	*)
		show_help
		;;
	esac
	shift
done
