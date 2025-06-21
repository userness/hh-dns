addEventListener('fetch', event => {
  event.respondWith(handleRequest(event.request))
})

const domainMappings = {
  'hh': 'netlify.app',
  'pg': 'pages.dev'
}

// Cache for DNS responses to avoid repeated lookups
const dnsCache = new Map()
const CACHE_TTL = 300000 // 5 minutes in milliseconds

async function handleRequest(request) {
  try {
    const url = new URL(request.url)
    
    // Handle DNS over HTTPS queries
    if (url.pathname === '/dns-query') {
      return handleDNSQuery(request)
    }
    
    // Handle regular HTTP requests (proxy functionality)
    return handleProxy(request)
  } catch (error) {
    console.error('Request handling error:', error)
    return new Response('Internal Server Error', { status: 500 })
  }
}

async function handleDNSQuery(request) {
  try {
    const url = new URL(request.url)
    let dnsQuery
    
    if (request.method === 'GET') {
      const dnsParam = url.searchParams.get('dns')
      if (!dnsParam) {
        return new Response('Missing dns parameter', { status: 400 })
      }
      dnsQuery = base64UrlDecode(dnsParam)
    } else if (request.method === 'POST') {
      const buffer = await request.arrayBuffer()
      dnsQuery = buffer
    } else {
      return new Response('Method not allowed', { status: 405 })
    }
    
    const domain = parseDNSQuery(dnsQuery)
    
    if (!domain) {
      return forwardDNSQuery(dnsQuery)
    }
    
    // Check cache first
    const cacheKey = `dns:${domain}`
    const cached = dnsCache.get(cacheKey)
    if (cached && Date.now() - cached.timestamp < CACHE_TTL) {
      const dnsResponse = createDNSResponse(dnsQuery, cached.ip)
      return new Response(dnsResponse, {
        headers: {
          'Content-Type': 'application/dns-message',
          'Cache-Control': 'max-age=300'
        }
      })
    }
    
    // Check for custom domain mapping
    for (const [extension, target] of Object.entries(domainMappings)) {
      if (domain.endsWith(`.${extension}`)) {
        const baseDomain = domain.slice(0, -(extension.length + 1))
        const targetHost = `${baseDomain}.${target}`
        
        // Resolve target and create DNS response
        const ip = await resolveIP(targetHost)
        if (ip) {
          // Cache the result
          dnsCache.set(cacheKey, { ip, timestamp: Date.now() })
          
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
    console.error('DNS query error:', error)
    return new Response('DNS query error', { status: 500 })
  }
}

async function handleProxy(request) {
  try {
    const url = new URL(request.url)
    const hostname = url.hostname
    
    // Check if domain matches any of our patterns
    for (const [extension, target] of Object.entries(domainMappings)) {
      if (hostname.endsWith(`.${extension}`)) {
        const baseDomain = hostname.slice(0, -(extension.length + 1))
        const targetHost = `${baseDomain}.${target}`
        
        const targetUrl = new URL(request.url)
        targetUrl.hostname = targetHost
        
        // Clone request with proper headers
        const newRequest = new Request(targetUrl, {
          method: request.method,
          headers: new Headers(request.headers),
          body: request.method === 'GET' || request.method === 'HEAD' ? null : request.body,
          redirect: 'manual'
        })
        
        // Set proper host header
        newRequest.headers.set('Host', targetHost)
        
        const response = await fetch(newRequest)
        
        // Clone response and modify headers
        const newResponse = new Response(response.body, {
          status: response.status,
          statusText: response.statusText,
          headers: new Headers(response.headers)
        })
        
        // Remove security headers that might interfere with proxying
        newResponse.headers.delete('content-security-policy')
        newResponse.headers.delete('x-frame-options')
        newResponse.headers.delete('strict-transport-security')
        
        // Set CORS headers if needed
        if (request.headers.get('Origin')) {
          newResponse.headers.set('Access-Control-Allow-Origin', '*')
          newResponse.headers.set('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS')
          newResponse.headers.set('Access-Control-Allow-Headers', 'Content-Type, Authorization')
        }
        
        return newResponse
      }
    }
    
    // Forward request as-is if no mapping found
    return fetch(request)
  } catch (error) {
    console.error('Proxy error:', error)
    return new Response('Proxy error', { status: 502 })
  }
}

async function forwardDNSQuery(dnsQuery) {
  try {
    const response = await fetch('https://cloudflare-dns.com/dns-query', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/dns-message',
        'Accept': 'application/dns-message'
      },
      body: dnsQuery
    })
    
    if (!response.ok) {
      throw new Error(`DNS forward failed: ${response.status}`)
    }
    
    return new Response(response.body, {
      status: response.status,
      headers: {
        'Content-Type': 'application/dns-message',
        'Cache-Control': 'max-age=300'
      }
    })
  } catch (error) {
    console.error('DNS forward error:', error)
    return new Response('DNS resolution failed', { status: 502 })
  }
}

async function resolveIP(hostname) {
  try {
    const response = await fetch(`https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(hostname)}&type=A`, {
      headers: { 
        'Accept': 'application/dns-json',
        'User-Agent': 'CloudflareWorker/1.0'
      }
    })
    
    if (!response.ok) {
      console.error(`DNS resolution failed for ${hostname}: ${response.status}`)
      return null
    }
    
    const data = await response.json()
    
    // Return the first A record if available
    const aRecord = data.Answer?.find(record => record.type === 1)
    return aRecord?.data || null
  } catch (error) {
    console.error(`Error resolving ${hostname}:`, error)
    return null
  }
}

function parseDNSQuery(dnsQuery) {
  try {
    const view = new DataView(dnsQuery)
    
    // Validate minimum DNS query size
    if (dnsQuery.byteLength < 12) {
      return null
    }
    
    let offset = 12 // Skip DNS header
    const parts = []
    
    while (offset < dnsQuery.byteLength) {
      const length = view.getUint8(offset)
      
      if (length === 0) {
        break // End of domain name
      }
      
      if (length > 63) {
        // Handle DNS compression (pointer)
        break
      }
      
      offset++
      
      if (offset + length > dnsQuery.byteLength) {
        break // Prevent buffer overflow
      }
      
      const part = new TextDecoder('utf-8', { fatal: true }).decode(
        dnsQuery.slice(offset, offset + length)
      )
      parts.push(part)
      offset += length
    }
    
    return parts.length > 0 ? parts.join('.') : null
  } catch (error) {
    console.error('DNS parsing error:', error)
    return null
  }
}

function createDNSResponse(query, ip) {
  try {
    // Validate IP format
    const ipParts = ip.split('.')
    if (ipParts.length !== 4 || !ipParts.every(part => {
      const num = parseInt(part, 10)
      return num >= 0 && num <= 255 && part === num.toString()
    })) {
      throw new Error('Invalid IP address format')
    }
    
    const response = new Uint8Array(query.byteLength + 16)
    response.set(new Uint8Array(query))
    
    // Set response flags (standard query response, no error)
    response[2] = 0x81 // QR=1, Opcode=0, AA=0, TC=0, RD=1
    response[3] = 0x80 // RA=1, Z=0, RCODE=0
    
    // Set answer count to 1
    response[6] = 0x00
    response[7] = 0x01
    
    // Add answer section
    let offset = query.byteLength
    
    // Name (compressed pointer to question)
    response[offset++] = 0xc0
    response[offset++] = 0x0c
    
    // Type A (1)
    response[offset++] = 0x00
    response[offset++] = 0x01
    
    // Class IN (1)
    response[offset++] = 0x00
    response[offset++] = 0x01
    
    // TTL (300 seconds)
    response[offset++] = 0x00
    response[offset++] = 0x00
    response[offset++] = 0x01
    response[offset++] = 0x2c
    
    // Data length (4 bytes for IPv4)
    response[offset++] = 0x00
    response[offset++] = 0x04
    
    // IP address (4 bytes)
    for (const part of ipParts) {
      response[offset++] = parseInt(part, 10)
    }
    
    return response.buffer
  } catch (error) {
    console.error('DNS response creation error:', error)
    throw error
  }
}

function base64UrlDecode(str) {
  try {
    // Convert base64url to base64
    str = str.replace(/-/g, '+').replace(/_/g, '/')
    
    // Add padding if needed
    while (str.length % 4) {
      str += '='
    }
    
    // Decode base64
    const binary = atob(str)
    const bytes = new Uint8Array(binary.length)
    
    for (let i = 0; i < binary.length; i++) {
      bytes[i] = binary.charCodeAt(i)
    }
    
    return bytes.buffer
  } catch (error) {
    console.error('Base64 decode error:', error)
    throw new Error('Invalid base64url encoding')
  }
}

// Clean up old cache entries periodically
setInterval(() => {
  const now = Date.now()
  for (const [key, value] of dnsCache.entries()) {
    if (now - value.timestamp > CACHE_TTL) {
      dnsCache.delete(key)
    }
  }
}, 60000) // Clean up every minute