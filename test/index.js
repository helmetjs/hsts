var hsts = require('..')

var assert = require('assert')
var connect = require('connect')
var request = require('supertest')

describe('hsts', function () {
  function app (options) {
    var result = connect()
    result.use(hsts(options))
    result.use(function (req, res) {
      res.end('Hello world!')
    })
    return result
  }

  it('throws an error with invalid parameters', function () {
    assert.throws(hsts.bind(this, { maxAge: -123 }))
    assert.throws(hsts.bind(this, { maxAge: '123' }))
    assert.throws(hsts.bind(this, { maxAge: true }))
    assert.throws(hsts.bind(this, { maxAge: false }))
    assert.throws(hsts.bind(this, { maxAge: {} }))
    assert.throws(hsts.bind(this, { maxAge: [] }))

    assert.throws(hsts.bind(this, { maxAge: 1234 }, 'extra argument'))

    assert.throws(hsts.bind(this, { setIf: 123 }))
    assert.throws(hsts.bind(this, { setIf: true }))
    assert.throws(hsts.bind(this, { setIf: false }))
    assert.throws(hsts.bind(this, { setIf: null }))

    assert.throws(hsts.bind(this, { maxage: false }))
    assert.throws(hsts.bind(this, { maxage: 1234 }))
    assert.throws(hsts.bind(this, {
      includeSubDomains: true,
      includeSubdomains: true
    }))
    assert.throws(hsts.bind(this, {
      includeSubDomains: false,
      includeSubdomains: true
    }))
  })

  it('by default, sets max-age to 180 days and adds "includeSubDomains"', function () {
    assert.equal(15552000, 180 * 24 * 60 * 60)

    return request(app())
      .get('/')
      .expect(200)
      .expect('Strict-Transport-Security', 'max-age=15552000; includeSubDomains')
  })

  it('can set max-age to a positive integer', function () {
    return request(app({
      maxAge: 1234
    }))
      .get('/')
      .expect(200)
      .expect('Strict-Transport-Security', 'max-age=1234; includeSubDomains')
  })

  it('rounds the max-age', function () {
    return request(app({
      maxAge: 1234.56
    }))
      .get('/')
      .expect(200)
      .expect('Strict-Transport-Security', 'max-age=1235; includeSubDomains')
  })

  it('can set max-age to -0', function () {
    return request(app({
      maxAge: -0
    }))
      .get('/')
      .expect(200)
      .expect('Strict-Transport-Security', 'max-age=0; includeSubDomains')
  })

  it('can set max-age to 0', function () {
    return request(app({
      maxAge: 0
    }))
      .get('/')
      .expect(200)
      .expect('Strict-Transport-Security', 'max-age=0; includeSubDomains')
  })

  it('can disable subdomains with the includeSubDomains option', function () {
    return request(app({
      includeSubDomains: false
    }))
      .get('/')
      .expect(200)
      .expect('Strict-Transport-Security', 'max-age=15552000')
  })

  it('can disable subdomains with the includeSubdomains option', function () {
    return request(app({
      includeSubdomains: false
    }))
      .get('/')
      .expect(200)
      .expect('Strict-Transport-Security', 'max-age=15552000')
  })

  it('can enable preloading', function () {
    return request(app({
      preload: true
    }))
      .get('/')
      .expect(200)
      .expect('Strict-Transport-Security', 'max-age=15552000; includeSubDomains; preload')
  })

  it('can set the header based on your own condition', function () {
    var server = app({
      setIf: function (req) {
        return req.headers['x-should-set'] === 'yes'
      }
    })

    return request(server)
      .get('/')
      .set('X-Should-Set', 'no')
      .expect(200)
      .then(function (res) {
        assert(!('strict-transport-security' in res.headers))
      })
      .then(function () {
        return request(server)
          .get('/')
          .set('X-Should-Set', 'yes')
          .expect(200)
          .expect('Strict-Transport-Security', 'max-age=15552000; includeSubDomains')
      })
  })

  it('does nothing with the `force` option; allowed for backwards compatibility', function () {
    return request(app({ force: true }))
      .get('/')
      .expect(200)
      .expect('Strict-Transport-Security', 'max-age=15552000; includeSubDomains')
  })

  it('names its function and middleware', function () {
    assert.equal(hsts.name, 'hsts')
    assert.equal(hsts().name, 'hsts')
  })
})
