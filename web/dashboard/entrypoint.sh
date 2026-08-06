#!/bin/sh
# Renders config.js and the CSP connect-src from the environment, then hands off
# to nginx. Runs on every container start, so the URLs are deployment config
# rather than something baked into the image.
#
# Rendering is idempotent: both outputs are generated from pristine templates
# that are never overwritten, so restarting a container with changed env picks
# up the new values instead of reusing the previous render.
set -eu

: "${ARKD_ADMIN_URL:?ARKD_ADMIN_URL is required, e.g. https://arkd:7071}"
ARKD_INDEXER_URL="${ARKD_INDEXER_URL:-}"

# Strip trailing slashes so the app can concatenate paths safely.
ARKD_ADMIN_URL="${ARKD_ADMIN_URL%/}"
ARKD_INDEXER_URL="${ARKD_INDEXER_URL%/}"

# Both values are interpolated into a JS string literal and into the CSP, the
# latter via a sed replacement. A quote would break out of the literal and a
# pipe would break the sed expression, either of which silently produces a
# broken page or a CSP that no longer pins the origins. Refuse instead.
check_url() {
  name=$1
  value=$2
  case "$value" in
    http://*|https://*) ;;
    *)
      echo "$name must start with http:// or https://, got '$value'" >&2
      exit 1
      ;;
  esac
  case "$value" in
    *[\"\'\\\|\;\&\<\>\ ]*|*'`'*|*'$'*)
      echo "$name contains a character that is not valid in a URL: '$value'" >&2
      exit 1
      ;;
  esac
}

check_url ARKD_ADMIN_URL "$ARKD_ADMIN_URL"
if [ -n "$ARKD_INDEXER_URL" ]; then
  check_url ARKD_INDEXER_URL "$ARKD_INDEXER_URL"
fi

export ARKD_ADMIN_URL ARKD_INDEXER_URL

# Overridable so the rendering step can be exercised outside the image.
ROOT="${ROOT:-/usr/share/nginx/html}"

envsubst '${ARKD_ADMIN_URL} ${ARKD_INDEXER_URL}' \
  < "$ROOT/config.js.tpl" > "$ROOT/config.js.new"
mv "$ROOT/config.js.new" "$ROOT/config.js"

# connect-src has to name the origins the page is allowed to reach. Pinning it
# to exactly these two is what stops a compromised page from shipping the
# macaroon somewhere else.
CONNECT_SRC="'self' $ARKD_ADMIN_URL"
if [ -n "$ARKD_INDEXER_URL" ]; then
  CONNECT_SRC="$CONNECT_SRC $ARKD_INDEXER_URL"
fi

# Keep the un-substituted original so re-runs render from the placeholder rather
# than from a previous render. Avoids `sed -i`, which is not portable.
[ -f "$ROOT/index.html.tpl" ] || cp "$ROOT/index.html" "$ROOT/index.html.tpl"
sed "s|ARKD_CONNECT_SRC|$CONNECT_SRC|" "$ROOT/index.html.tpl" > "$ROOT/index.html.new"
mv "$ROOT/index.html.new" "$ROOT/index.html"

echo "arkd console -> admin $ARKD_ADMIN_URL, indexer ${ARKD_INDEXER_URL:-<disabled>}"

exec nginx -g 'daemon off;'
