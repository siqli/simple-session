import { parse } from 'cookie'

// https://newbedev.com/create-a-unique-session-id-in-javascript-code-example
const ID = () => Math.random().toString(36).split('.')[1]

// Allowing from everywhere by default.
const headers = {
  'Access-Control-Allow-Headers': '*',
  'Access-Control-Allow-Methods': "GET, OPTIONS",
  'Access-Control-Allow-Origin': '*',
}

// digestMessage from MDN
// https://developer.mozilla.org/en-US/docs/Web/API/SubtleCrypto/digest#converting_a_digest_to_a_hex_string
async function digestMessage(message) {
  const msgUint8 = new TextEncoder().encode(message)                           // encode as (utf-8) Uint8Array
  const hashBuffer = await crypto.subtle.digest('SHA-256', msgUint8)           // hash the message
  const hashArray = Array.from(new Uint8Array(hashBuffer))                     // convert buffer to byte array
  const hashHex = hashArray.map(b => b.toString(16).padStart(2, '0')).join('') // convert bytes to hex string
  return hashHex
}

/**
 * 
 * @param {Request} req 
 * @param {Env} env 
 * @returns
 */
async function createSession(req, env) {

  //
  const { hostname } = new URL(req.url)

  // Generate session ID
  const sessionID = ID()

  // Now
  const now = Date.now()

  // Generate session token
  const sessionToken = await digestMessage(`${sessionID}-${env.SESSION_KEY}-${now}`)

  try {
    // Store session ID & token
    await env.SESSION_STORE.put(sessionID, sessionToken, {
      // Set token to expire in `x` seconds
      expirationTtl: env.EXPIRATION_TTL || 300
    })

    // Return
    let response = new Response(
      JSON.stringify(
        [ sessionID, sessionToken ]
      ), {
        status: 201,    // 201 Created
        headers: {
          ...headers,
          'Content-Type': 'application/json;charset=utf-8',
        }
      }
    )

    // Append Set-Cookie headers
    response.headers.append(
      'Set-Cookie',
      `ssID=${sessionID}; Domain=${hostname}; Path=/; Secure; SameSite=Strict`
    )
    response.headers.append(
      'Set-Cookie',
      `ssTkn=${sessionToken}; Domain=${hostname}; Path=/; Secure; SameSite=Strict`
    )

    // Return response
    return response
  } catch(e) {

    // Return error
    return new Response(
      JSON.stringify({
        err: e.message || e.toString()
      }), {
        status: 500,    // 500 Internal Server Error
        headers: {
          ...headers,
          'Content-Type': 'application/json;charset=utf-8',
        }
      }
    )
  }
}

/**
 * 
 * @param {Request} req
 * @param {Env} env 
 * @returns 
 */
async function verifySession(req, env) {

  try {
    // Read session ID/token
    const cookie = parse(req.headers.get('Cookie') || '')
    const sessionID = cookie['ssID'] || undefined
    const sessionToken = cookie['ssTkn'] || undefined

    // Check against stored value
    const storedValue = await env.SESSION_STORE.get(sessionID)

    // Verfied
    if (storedValue === sessionToken)
      return new Response("OK", {
        status: 200,    // OK
        headers: {
          ...headers,
          'Content-Type': 'application/json;charset=utf-8',
        }
      })

    // Not verified (invalid/expired)
    let response = new Response(null, {
        status: 204,      // 204 No Content. Or is 401 Unauthorised better?
        headers: {
          ...headers,
        }
      }
    )

    // Append Set-Cookie headers to "delete" cookies
    response.headers.append('Set-Cookie', `ssID=''; max-age=0`)
    response.headers.append('Set-Cookie', `ssTkn=''; max-age=0`)

    // Return response
    return response
  } catch(e) {

    // Likely ???
    return new Response(
      JSON.stringify({
        err: e.message || e.toString
      }), {
        status: 500,    // 500 Internal Server Error
        headers: {
          ...headers,
          'Content-Type': 'application/json;charset=utf-8',
        }
      }
    )
  }
}

/**
 * 
 * @param {Request} req 
 * @param {Env} env 
 * @returns 
 */
function handleRequest(req, env) {

  const { pathname } = new URL(req.url)

  // 
  if (req.method === "OPTIONS")
    return new Response("OK", { headers })

  // Check token validity
  if (req.method === "GET" && pathname === "/verify")
    return verifySession(req, env)

  // Issue new session token
  if (req.method === "GET" && pathname === "/new")
    return createSession(req, env)

  // Not valid
  return new Response(
    JSON.stringify({
      err: "Bad Request"
    }), {
      status: 400,    // 400 Bad Request
      headers: {
        ...headers,
        'Content-Type': 'application/json;charset=utf-8',
      }
    }
  )

}

/**
 * 
 */
export default {
  fetch: handleRequest
}
