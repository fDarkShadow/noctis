FROM docker.io/library/php:7.4-apache

# PHPUnit eval-stdin.php exposed at the standard composer vendor path
# PHP code sent in the POST body is evaluated via php://stdin → RCE (CVE-2017-9841)
# HTTP (80) + HTTPS (443) with self-signed cert
RUN mkdir -p /var/www/html/vendor/phpunit/phpunit/src/Util/PHP \
             /var/www/html/vendor/phpunit/phpunit/Util/PHP && \
    printf '<?php eval("?>" . file_get_contents("php://input")); ?>\n' \
      > /var/www/html/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php && \
    cp /var/www/html/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php \
       /var/www/html/vendor/phpunit/phpunit/Util/PHP/eval-stdin.php && \
    a2enmod ssl && \
    mkdir -p /etc/apache2/ssl && \
    openssl req -x509 -newkey rsa:2048 \
        -keyout /etc/apache2/ssl/key.pem \
        -out /etc/apache2/ssl/cert.pem \
        -days 3650 -nodes -subj "/CN=localhost" && \
    printf '<VirtualHost *:443>\n  SSLEngine on\n  SSLCertificateFile /etc/apache2/ssl/cert.pem\n  SSLCertificateKeyFile /etc/apache2/ssl/key.pem\n  DocumentRoot /var/www/html\n</VirtualHost>\n' \
      > /etc/apache2/sites-enabled/ssl.conf

EXPOSE 80 443
