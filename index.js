addEventListener("fetch", event => {
  event.respondWith(handleRequest(event.request));
});

async function handleRequest(request) {
  const url = new URL(request.url);
  const domain = url.searchParams.get("hostname");
  const type = url.searchParams.get("type") || "A";

  if (!domain) {
    return new Response("Missing 'hostname' query parameter", { status: 400 });
  }

  const mappedDomain = transformDomain(domain);

  if (!mappedDomain) {
    return new Response("No matching custom domain pattern", { status: 400 });
  }

  const resolvedIP = await resolveDomain(mappedDomain, type);
  if (resolvedIP) {
    return Response.json([{ name: domain, type, data: resolvedIP }]);
  } else {
    return new Response("DNS resolution failed", { status: 404 });
  }
}

function transformDomain(domain) {
  if (domain.endsWith(".hh")) {
    const base = domain.slice(0, -3); // remove .hh
    return `${base}-hh.netlify.app`;
  }
  if (domain.endsWith(".pg")) {
    const base = domain.slice(0, -3); // remove .pg
    return `${base}-hh.pages.dev`;
  }
  return null;
}

async function resolveDomain(domain, type = "A") {
  const url = `https://hh-dns.auth-microsoft-no-reply.workers.dev/dns-query?name=${domain}&type=${type}`;
  const res = await fetch(url, {
    headers: { accept: "application/dns-json" }
  });

  if (!res.ok) return null;

  const data = await res.json();
  const answer = data.Answer?.find(r => r.type === (type === "AAAA" ? 28 : 1));
  return answer?.data || null;
}