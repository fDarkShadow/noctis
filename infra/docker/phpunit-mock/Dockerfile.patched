FROM docker.io/library/php:7.4-apache

# PHPUnit not installed — /vendor/phpunit path does not exist → 404
# Any POST to eval-stdin.php returns 404, no code evaluation
# HTTP (80) + HTTPS (443) with self-signed cert
RUN a2enmod ssl && \
    mkdir -p /etc/apache2/ssl && \
    openssl req -x509 -newkey rsa:2048 \
        -keyout /etc/apache2/ssl/key.pem \
        -out /etc/apache2/ssl/cert.pem \
        -days 3650 -nodes -subj "/CN=localhost" && \
    printf '<VirtualHost *:443>\n  SSLEngine on\n  SSLCertificateFile /etc/apache2/ssl/cert.pem\n  SSLCertificateKeyFile /etc/apache2/ssl/key.pem\n  DocumentRoot /var/www/html\n</VirtualHost>\n' \
      > /etc/apache2/sites-enabled/ssl.conf

EXPOSE 80 443
