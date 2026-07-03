const net = require('node:net')

function parseIpv4(value) {
  const parts = String(value || '').split('.')
  if (parts.length !== 4) return null
  const nums = parts.map(part => {
    if (!/^\d+$/.test(part)) return NaN
    const n = Number(part)
    return n >= 0 && n <= 255 ? n : NaN
  })
  return nums.every(Number.isFinite) ? nums : null
}

function isPrivateIpv4(hostname) {
  const parts = parseIpv4(hostname)
  if (!parts) return false
  const [a, b] = parts

  return (
    a === 0 ||
    a === 10 ||
    a === 127 ||
    (a === 169 && b === 254) ||
    (a === 172 && b >= 16 && b <= 31) ||
    (a === 192 && b === 168)
  )
}

function ipv4FromMappedIpv6(hostname) {
  const host = String(hostname || '').toLowerCase()
  if (!host.startsWith('::ffff:')) return null
  const tail = host.slice('::ffff:'.length)
  const dotted = parseIpv4(tail)
  if (dotted) return dotted.join('.')

  const groups = tail.split(':')
  if (groups.length !== 2) return null
  const nums = groups.map(group => {
    if (!/^[0-9a-f]{1,4}$/i.test(group)) return NaN
    return parseInt(group, 16)
  })
  if (!nums.every(Number.isFinite)) return null

  return [nums[0] >> 8, nums[0] & 0xff, nums[1] >> 8, nums[1] & 0xff].join('.')
}

function isPrivateIpv6(hostname) {
  const host = String(hostname || '').toLowerCase()
  if (!host) return false
  const mappedIpv4 = ipv4FromMappedIpv6(host)
  if (mappedIpv4) return isPrivateIpv4(mappedIpv4)

  return (
    host === '::1' ||
    host === '::' ||
    host.startsWith('fe80:') ||
    host.startsWith('fc') ||
    host.startsWith('fd')
  )
}

function isBlockedLinkTitleUrl(rawUrl) {
  let parsed
  try {
    parsed = new URL(String(rawUrl || '').trim())
  } catch {
    return true
  }

  if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
    return true
  }

  const hostname = parsed.hostname.replace(/^\[|\]$/g, '').toLowerCase()
  if (!hostname) return true
  if (hostname === 'localhost' || hostname.endsWith('.localhost')) return true

  const ipVersion = net.isIP(hostname)
  if (ipVersion === 4) return isPrivateIpv4(hostname)
  if (ipVersion === 6) return isPrivateIpv6(hostname)

  return false
}

module.exports = {
  isBlockedLinkTitleUrl
}
