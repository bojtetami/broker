const SAFE_HOSTNAME_PATTERN = /^[a-zA-Z0-9.-]+$/

export function sanitizeRequestUrl (rawUrl: string): string {
  const parsed = new URL(rawUrl)
  if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
    throw new Error(`Unsupported protocol: ${parsed.protocol}`)
  }
  if (parsed.username || parsed.password) {
    throw new Error('URL credentials are not allowed')
  }
  const hostname = parsed.hostname.toLowerCase()
  if (!SAFE_HOSTNAME_PATTERN.test(hostname)) {
    throw new Error('URL host is not allowed')
  }
  const port = parsed.port ? `:${parsed.port}` : ''
  return `${parsed.protocol}//${hostname}${port}${parsed.pathname}${parsed.search}`
}

export function assertSafeForwardHostname (hostname: string): void {
  if (!SAFE_HOSTNAME_PATTERN.test(hostname)) {
    throw new Error('URL host is not allowed')
  }
}

export function toHttpRequestOptions (sanitizedUrl: string): {
  protocol: string
  hostname: string
  port: number | string
  path: string
} {
  const validatedUrl = sanitizeRequestUrl(sanitizedUrl)
  const parsed = new URL(validatedUrl)
  const hostnameMatch = parsed.hostname.toLowerCase().match(/^([a-z0-9.-]+)$/)
  if (!hostnameMatch) {
    throw new Error('URL host is not allowed')
  }
  const pathMatch = `${parsed.pathname}${parsed.search}`.match(/^(\/[^\0]*)$/)
  if (!pathMatch || pathMatch[1].includes('..')) {
    throw new Error('Invalid path')
  }
  const port = parsed.port ? Number(parsed.port) : (parsed.protocol === 'https:' ? 443 : 80)
  if (!Number.isInteger(port) || port < 1 || port > 65535) {
    throw new Error('Invalid port')
  }
  return {
    protocol: parsed.protocol === 'https:' ? 'https:' : 'http:',
    hostname: hostnameMatch[1],
    port,
    path: pathMatch[1],
  }
}
