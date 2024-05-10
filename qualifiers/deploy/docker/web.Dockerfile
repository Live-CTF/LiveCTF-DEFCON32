FROM docker.io/nginx

COPY web-frontend/src /usr/share/nginx/html
COPY web-frontend/conf/nginx.conf /etc/nginx/nginx.conf
COPY web-frontend/conf/proxy_params /etc/nginx/proxy_params
COPY web-frontend/conf/conf.d/default.conf /etc/nginx/conf.d/default.conf
