addEventListener('fetch', event => {
  event.respondWith(handleRequest(event.request))
})

const domainMappings = {
  'hh': 'netlify.app',
  'pg': 'pages.dev'
}

async function handleRequest(request) {
  const url = new URL(request.url)
  const hostname = url.hostname
  
  // Check if domain matches any of our patterns
  for (const [extension, target] of Object.entries(domainMappings)) {
    if (hostname.endsWith(`.${extension}`)) {
      const baseDomain = hostname.slice(0, -(extension.length + 1))
      const targetHost = `${baseDomain}-hh.${target}`
      
      // Create new URL with target host but keep original path/query
      const targetUrl = new URL(request.url)
      targetUrl.hostname = targetHost
      
      // Create new request to target
      const newRequest = new Request(targetUrl, {
        method: request.method,
        headers: request.headers,
        body: request.body
      })
      
      // Fetch from target and return response
      const response = await fetch(newRequest)
      
      // Create new response with modified headers
      const newResponse = new Response(response.body, {
        status: response.status,
        statusText: response.statusText,
        headers: response.headers
      })
      
      // Remove headers that might break the proxy
      newResponse.headers.delete('content-security-policy')
      newResponse.headers.delete('x-frame-options')
      
      return newResponse
    }
  }
  
  // For all other domains, just pass through normally
  return fetch(request)
}