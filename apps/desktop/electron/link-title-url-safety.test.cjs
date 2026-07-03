'use strict'

const assert = require('node:assert/strict')
const test = require('node:test')

const { isBlockedLinkTitleUrl } = require('./link-title-url-safety.cjs')

test('isBlockedLinkTitleUrl allows public http and https URLs', () => {
  assert.equal(isBlockedLinkTitleUrl('https://example.com/article'), false)
  assert.equal(isBlockedLinkTitleUrl('http://93.184.216.34/'), false)
})

test('isBlockedLinkTitleUrl rejects non-http schemes', () => {
  assert.equal(isBlockedLinkTitleUrl('file:///tmp/secret.html'), true)
  assert.equal(isBlockedLinkTitleUrl('javascript:alert(1)'), true)
  assert.equal(isBlockedLinkTitleUrl('data:text/html,<title>x</title>'), true)
})

test('isBlockedLinkTitleUrl rejects loopback, private, and metadata IPv4 URLs', () => {
  assert.equal(isBlockedLinkTitleUrl('http://localhost:8000/'), true)
  assert.equal(isBlockedLinkTitleUrl('http://127.0.0.1:8000/'), true)
  assert.equal(isBlockedLinkTitleUrl('http://10.0.0.2/'), true)
  assert.equal(isBlockedLinkTitleUrl('http://172.16.0.5/'), true)
  assert.equal(isBlockedLinkTitleUrl('http://192.168.1.10/'), true)
  assert.equal(isBlockedLinkTitleUrl('http://169.254.169.254/latest/meta-data/'), true)
})

test('isBlockedLinkTitleUrl rejects loopback, link-local, and unique-local IPv6 URLs', () => {
  assert.equal(isBlockedLinkTitleUrl('http://[::1]/'), true)
  assert.equal(isBlockedLinkTitleUrl('http://[fe80::1]/'), true)
  assert.equal(isBlockedLinkTitleUrl('http://[fd00::1]/'), true)
  assert.equal(isBlockedLinkTitleUrl('http://[::ffff:127.0.0.1]/'), true)
  assert.equal(isBlockedLinkTitleUrl('http://[::ffff:169.254.169.254]/'), true)
})
