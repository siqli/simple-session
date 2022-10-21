// https://newbedev.com/create-a-unique-session-id-in-javascript-code-example
const ID = () => Math.random().toString(36).split('.')[1]

/**
 * Allowing from everywhere by default.
 */
const headers = {
  'Access-Control-Allow-Headers': '*',
  'Access-Control-Allow-Methods': "GET, OPTIONS",
  'Access-Control-Allow-Origin': '*',
}

// digestMessage from MDN
// https://developer.mozilla.org/en-US/docs/Web/API/SubtleCrypto/digest#converting_a_digest_to_a_hex_string
async function digestMessage(message) {
  const msgUint8 = new TextEncoder().encode(message);                           // encode as (utf-8) Uint8Array
  const hashBuffer = await crypto.subtle.digest('SHA-256', msgUint8);           // hash the message
  const hashArray = Array.from(new Uint8Array(hashBuffer));                     // convert buffer to byte array
  const hashHex = hashArray.map(b => b.toString(16).padStart(2, '0')).join(''); // convert bytes to hex string
  return hashHex;
}

/**
 * 
 * @param {Request} req 
 * @param {Env} env 
 * @returns {JSON}
 */
async function createSession(req, env) {

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
    return new Response(
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
 * @param {URLPattern} payload 
 * @param {Env} env 
 * @returns 
 */
async function verifySession(payload, env) {

  try {
    // Read session ID/token
    const sessionID = payload.pathname.groups.sessionId
    const sessionToken = payload.pathname.groups.sessionToken

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
    return new Response(
      JSON.stringify({
        // If sessionID isn't found, storedValue is `null`
        err: `Session ${storedValue === null ? "ID" : "token"} invalid`
      }), {
        status: 401,      // 401 Unauthorised
        headers: {
          ...headers,
          'Content-Type': 'application/json;charset=utf-8',
        }
      }
    )
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
async function handleRequest(req, env) {

  // 
  if (req.method === "OPTIONS")
    return new Response("OK", { headers })

  // Check route
  const verifyRoute = new URLPattern({ pathname: "/verify/:sessionId/:sessionToken" })
  const verifyMatch = verifyRoute.exec(req.url)

  // Check token validity
  if (req.method === "GET" && verifyMatch)
    return await verifySession(verifyMatch, env)

  // Issue new session token
  if (req.method === "GET" && new URL(req.url).pathname === "/new")
    return await createSession(req, env)

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
