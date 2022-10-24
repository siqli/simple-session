# Simple Session Tokens

Use [Cloudflare Workers](https://siq.li/cfw) & [Workers KV](https://siq.li/aXY) to generate/store/verify session ID/token.

This doesn't use expiring JWTs *(though it could)* rather uses the [expiring keys](https://siq.li/owy) feature of Workers KV.

#### Version 2

Version 2 uses `Set-Cookie` headers to set/expire cookies in response rather than handle it client-side and reads request cookies for verification rather than requiring sending as headers (`X-Session-ID` and `X-Session-Token`.)

## Session Store

Create a KV and add the `id` to the `SESSION_STORE` binding in `wrangler.toml`. Create a second KV for testing purposes and add to `preview_id` *(optional.)*

## Testing

An simple worker using `simple-session` as a [bound service](https://siq.li/cEq) is included in the `example` directory.

## LICENSE

[Jam](LICENSE)
