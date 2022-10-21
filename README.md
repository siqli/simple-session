# Simple Session Tokens

Use [Cloudflare Workers](https://siq.li/cfw) & [Workers KV](https://siq.li/aXY) to generate/store/verify session ID/token.

This doesn't use expiring JWTs *(though it could)* rather uses the [expiring keys](https://siq.li/owy) feature of Workers KV.
