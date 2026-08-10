# Static read-only operator console for arkd.
# No build step: the sources are the artifact.
FROM nginx:1.27-alpine

# Every module: a hand-kept list silently drops a new one and 404s the page.
COPY index.html style.css config.js.tpl *.js /usr/share/nginx/html/
COPY nginx.conf /etc/nginx/conf.d/default.conf
COPY entrypoint.sh /entrypoint.sh

RUN chmod +x /entrypoint.sh

EXPOSE 80
ENTRYPOINT ["/entrypoint.sh"]
