# Static read-only operator console for arkd.
# No build step: the sources are the artifact.
FROM nginx:1.27-alpine

RUN apk add --no-cache gettext

COPY index.html style.css config.js.tpl /usr/share/nginx/html/
COPY app.js api.js table.js panels.js fmt.js \
     solvency.js batch.js offchainTx.js indexer.js \
     /usr/share/nginx/html/
COPY nginx.conf /etc/nginx/conf.d/default.conf
COPY entrypoint.sh /entrypoint.sh

RUN chmod +x /entrypoint.sh

EXPOSE 80
ENTRYPOINT ["/entrypoint.sh"]
