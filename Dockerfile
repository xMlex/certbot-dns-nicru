FROM certbot/certbot:v2.9.0

RUN mkdir -p /opt/certbot
WORKDIR /opt/certbot

ADD . /opt/certbot

RUN python -m pip install -e /opt/certbot

ENTRYPOINT [ "certbot" ]

VOLUME /etc/letsencrypt /var/lib/letsencrypt /var/log/letsencrypt

WORKDIR /opt/certbot