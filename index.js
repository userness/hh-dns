addEventListener('fetch', event => {
  event.respondWith(handleRequest(event.request))
})

const domainMappings = {
  'hh': 'netlify.app',
  'pg': 'pages.dev'
}

async function handleRequest(request) {
  const url = new URL(request.url)
  
  // Handle DNS over HTTPS queries
  if (url.pathname === '/dns-query') {
    return handleDNSQuery(request)
  }
  
  // Handle regular HTTP requests (proxy functionality)
  return handleProxy(request)
}

async function handleDNSQuery(request) {
  try {
    // Parse DNS query from URL params or POST body
    const url = new URL(request.url)
    const dnsParam = url.searchParams.get('dns')
    
    if (!dnsParam) {
      return new Response('Missing dns parameter', { status: 400 })
    }
    
    // Decode base64url DNS query
    const dnsQuery = base64UrlDecode(dnsParam)
    const domain = parseDNSQuery(dnsQuery)
    
    if (!domain) {
      return forwardDNSQuery(dnsQuery)
    }
    
    // Check for custom domain mapping
    for (const [extension, target] of Object.entries(domainMappings)) {
      if (domain.endsWith(`.${extension}`)) {
        const baseDomain = domain.slice(0, -(extension.length + 1))
        const targetHost = `${baseDomain}-hh.${target}`
        
        // Resolve target and create DNS response
        const ip = await resolveIP(targetHost)
        if (ip) {
          const dnsResponse = createDNSResponse(dnsQuery, ip)
          return new Response(dnsResponse, {
            headers: {
              'Content-Type': 'application/dns-message',
              'Cache-Control': 'max-age=300'
            }
          })
        }
      }
    }
    
    // Forward to upstream DNS
    return forwardDNSQuery(dnsQuery)
    
  } catch (error) {
    return new Response('DNS query error', { status: 500 })
  }
}

async function handleProxy(request) {
  const url = new URL(request.url)
  const hostname = url.hostname
  
  // Check if domain matches any of our patterns
  for (const [extension, target] of Object.entries(domainMappings)) {
    if (hostname.endsWith(`.${extension}`)) {
      const baseDomain = hostname.slice(0, -(extension.length + 1))
      const targetHost = `${baseDomain}-hh.${target}`
      
      const targetUrl = new URL(request.url)
      targetUrl.hostname = targetHost
      
      const newRequest = new Request(targetUrl, {
        method: request.method,
        headers: request.headers,
        body: request.body
      })
      
      const response = await fetch(newRequest)
      
      const newResponse = new Response(response.body, {
        status: response.status,
        statusText: response.statusText,
        headers: response.headers
      })
      
      newResponse.headers.delete('content-security-policy')
      newResponse.headers.delete('x-frame-options')
      
      return newResponse
    }
  }
  
  return fetch(request)
}

async function forwardDNSQuery(dnsQuery) {
  const response = await fetch('https://1.1.1.1/dns-query', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/dns-message'
    },
    body: dnsQuery
  })
  
  return new Response(response.body, {
    headers: {
      'Content-Type': 'application/dns-message',
      'Cache-Control': 'max-age=300'
    }
  })
}

async function resolveIP(hostname) {
  try {
    const response = await fetch(`https://1.1.1.1/dns-query?name=${hostname}&type=A`, {
      headers: { 'Accept': 'application/dns-json' }
    })
    const data = await response.json()
    return data.Answer?.[0]?.data
  } catch {
    return null
  }
}

function parseDNSQuery(dnsQuery) {
  try {
    const view = new DataView(dnsQuery)
    let offset = 12 // Skip header
    const parts = []
    
    while (offset < dnsQuery.byteLength) {
      const length = view.getUint8(offset)
      if (length === 0) break
      
      offset++
      const part = new TextDecoder().decode(dnsQuery.slice(offset, offset + length))
      parts.push(part)
      offset += length
    }
    
    return parts.join('.')
  } catch {
    return null
  }
}

function createDNSResponse(query, ip) {
  const response = new Uint8Array(query.byteLength + 16)
  response.set(new Uint8Array(query))
  
  // Set response flags
  response[2] = 0x81
  response[3] = 0x80
  
  // Set answer count
  response[6] = 0x00
  response[7] = 0x01
  
  // Add answer section
  let offset = query.byteLength
  response[offset++] = 0xc0 // Name compression
  response[offset++] = 0x0c
  response[offset++] = 0x00 // Type A
  response[offset++] = 0x01
  response[offset++] = 0x00 // Class IN
  response[offset++] = 0x01
  response[offset++] = 0x00 // TTL
  response[offset++] = 0x00
  response[offset++] = 0x01
  response[offset++] = 0x2c
  response[offset++] = 0x00 // Data length
  response[offset++] = 0x04
  
  // IP address
  const ipParts = ip.split('.')
  for (const part of ipParts) {
    response[offset++] = parseInt(part)
  }
  
  return response.buffer
}

function base64UrlDecode(str) {
  str = str.replace(/-/g, '+').replace(/_/g, '/')
  while (str.length % 4) str += '='
  
  const binary = atob(str)
  const bytes = new Uint8Array(binary.length)
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i)
  }
  return bytes.buffer
}