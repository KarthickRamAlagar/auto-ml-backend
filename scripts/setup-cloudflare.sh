#!/usr/bin/env bash
# One-time Cloudflare setup for Auto ML. Run from the backend/ folder:  bash scripts/setup-cloudflare.sh
# Creates the D1 database, R2 bucket, mail queue and KV namespace, writes their ids into wrangler.jsonc,
# applies the migrations, and generates + uploads the secrets. Safe to re-run: existing resources are reused.
set -euo pipefail
cd "$(dirname "$0")/.."

need() { command -v "$1" >/dev/null || { echo "Missing: $1"; exit 1; }; }
need node; need npx
W="npx wrangler"
$W whoami >/dev/null 2>&1 || { echo "Not logged in. Running: wrangler login"; $W login; }

echo "== D1 database"
OUT=$($W d1 create auto-ml-db 2>&1 || true)
DB_ID=$(echo "$OUT" | grep -Eo '[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}' | head -1 || true)
if [ -z "$DB_ID" ]; then
  DB_ID=$($W d1 list --json | node -e 'let s="";process.stdin.on("data",d=>s+=d).on("end",()=>{const r=JSON.parse(s).find(x=>x.name==="auto-ml-db");console.log(r?r.uuid:"")})')
fi
[ -n "$DB_ID" ] || { echo "Could not determine the D1 id"; exit 1; }
echo "   id $DB_ID"

echo "== R2 bucket"
$W r2 bucket create auto-ml-files 2>&1 | tail -1 || true

echo "== Queue (background e-mail)"
$W queues create auto-ml-mail 2>&1 | tail -1 || echo "   (queue not created: if your plan has no Queues, delete the \"queues\" block in wrangler.jsonc; mail is then sent directly)"

echo "== KV namespace"
KV_ID=$($W kv namespace list | node -e 'let s="";process.stdin.on("data",d=>s+=d).on("end",()=>{const r=JSON.parse(s).find(x=>/auto-ml-CACHE$|auto-ml-cache$/i.test(x.title));console.log(r?r.id:"")})')
if [ -z "$KV_ID" ]; then
  KV_OUT=$($W kv namespace create CACHE 2>&1)
  KV_ID=$(echo "$KV_OUT" | grep -Eo '[0-9a-f]{32}' | head -1)
fi
[ -n "$KV_ID" ] || { echo "Could not determine the KV id"; exit 1; }
echo "   id $KV_ID"

echo "== Writing ids into wrangler.jsonc"
node -e '
const fs=require("fs");let s=fs.readFileSync("wrangler.jsonc","utf8");
s=s.replace(/("database_id":\s*")[^"]*(")/,`$1${process.argv[1]}$2`).replace(/("kv_namespaces":\s*\[\{\s*"binding":\s*"CACHE",\s*"id":\s*")[^"]*(")/,`$1${process.argv[2]}$2`);
fs.writeFileSync("wrangler.jsonc",s);' "$DB_ID" "$KV_ID"

echo "== Migrations (remote)"
$W d1 migrations apply auto-ml-db --remote

echo "== Secrets"
gen() { node -e 'console.log(require("crypto").randomBytes(48).toString("hex"))'; }
# the two shared secrets come from ../.env.production when scripts/prod-setup.mjs made them (so the ML service gets the same ones)
if [ -f ../.env.production ]; then
  GATEWAY_SECRET=$(grep -E '^GATEWAY_SECRET=' ../.env.production | cut -d= -f2- || true)
  STORE_SECRET=$(grep -E '^STORE_SECRET=' ../.env.production | cut -d= -f2- || true)
fi
GATEWAY=${GATEWAY_SECRET:-$(gen)}; STORE=${STORE_SECRET:-$(gen)}
for NAME in JWT_SECRET PASSWORD_PEPPER; do echo "$(gen)" | $W secret put "$NAME" >/dev/null && echo "   $NAME set"; done
echo "$GATEWAY" | $W secret put GATEWAY_SECRET >/dev/null && echo "   GATEWAY_SECRET set"
echo "$STORE"   | $W secret put STORE_SECRET   >/dev/null && echo "   STORE_SECRET set"

cat <<MSG

Done. Give the ML service (ml-service/cloudflare) these two values (shown once; keep them out of git):

  GATEWAY_SECRET=$GATEWAY
  STORE_SECRET=$STORE

Optional: npx wrangler secret put RESEND_API_KEY   (verification, reset and payment emails)
Next: deploy ml-service, then set PUBLIC_APP_URL / GOOGLE_CLIENT_ID in wrangler.jsonc and run: npm run deploy
MSG
