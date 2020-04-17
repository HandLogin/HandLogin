# Select the base image
FROM php:7.4.1-apache
# Enable modifications
RUN a2enmod headers
# Copy sources to /var/www/html
COPY src /var/www/html
# Change ownership & permissions of /var/www
RUN chown www-data /var/www/ -R && chmod 775 /var/www/ -R
# Heroku
CMD sed -i "s/80/$PORT/g" /etc/apache2/sites-enabled/000-default.conf /etc/apache2/ports.conf && docker-php-entrypoint apache2-foreground
