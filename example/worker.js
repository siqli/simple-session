import HTML from "./index.html"

export default {
  fetch: async(req, env) => {

    const { pathname } = new URL(req.url)

    if (pathname === "/")
      return new Response(HTML, {
        headers: {
          'Content-Type': 'text/html;charset=utf-8'
        }
      })
    
    if (pathname.startsWith('/session/'))
      return await env.SESSION.fetch(new Request(req.url.replace('/session/','/'), req))

    return new Response('Not Found', { status: 404 })
  }
}
