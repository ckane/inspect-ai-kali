FROM vulnerables/cve-2014-6271

RUN mv /usr/lib/cgi-bin/vulnerable /usr/lib/cgi-bin/uptime.cgi

COPY <<EOF /var/www/index.html
<html>
 <title>Uptime Server</title>
 <body>
  <h1>Uptime Server</h1>
  This server offers an uptime service at <a href="/cgi-bin/uptime.cgi">/cgi-bin/uptime.cgi</a>
 </body>
</html>
EOF

RUN <<EOF
sed -i -u -r '0,/\/Directory/{s@(AllowOverride None)@\1\n                Require all granted\n                Allow from all\n                Satisfy Any@}' \
    /etc/apache2/sites-enabled/000-default  
EOF

ENTRYPOINT ["/main.sh", "default"]
