// Unlike other tests, these require us to mock requests and responses.
// Because this header should only be set for HTTPS, which is hard to fake
// reliably, we call the middleware function directly, with fake request and
// response objects.

var hsts = require('..')

var assert = require('assert')
var sinon = require('sinon')

describe('hsts', function () {
  beforeEach(function () {
    this.req = { secure: true }
    this.res = { setHeader: sinon.spy() }
    this.next = sinon.spy()
  })

  it('throws an error with invalid parameters', function () {
    assert.throws(hsts.bind(this, { maxAge: -123 }))
    assert.throws(hsts.bind(this, { maxAge: '123' }))
    assert.throws(hsts.bind(this, { maxAge: true }))
    assert.throws(hsts.bind(this, { maxAge: {} }))
    assert.throws(hsts.bind(this, { maxAge: [] }))

    assert.throws(hsts.bind(this, { maxAge: 1234 }, 'extra argument'))

    assert.throws(hsts.bind(this, { setIf: 123 }))
    assert.throws(hsts.bind(this, { setIf: true }))

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
    assert.throws(hsts.bind(this, { setIf: function () {}, force: true }))
  })

  it('sets no header if req.secure is false', function () {
    this.req.secure = false

    hsts()(this.req, this.res, this.next)

    assert(this.next.calledOnce)
    assert(this.next.calledWithExactly())
    assert(!this.res.setHeader.called)
  })

  it('by default, sets max-age to 1 day and includeSubDomains', function () {
    hsts()(this.req, this.res, this.next)

    assert(this.next.calledOnce)
    assert(this.next.calledWithExactly())
    assert(this.res.setHeader.calledWithExactly('Strict-Transport-Security', 'max-age=86400; includeSubDomains'))
  })

  it('can set max-age to a positive integer', function () {
    hsts({
      maxAge: 1234
    })(this.req, this.res, this.next)

    assert(this.next.calledOnce)
    assert(this.next.calledWithExactly())
    assert(this.res.setHeader.calledWithExactly('Strict-Transport-Security', 'max-age=1234; includeSubDomains'))
  })

  it('rounds the max-age', function () {
    hsts({
      maxAge: 1234.56
    })(this.req, this.res, this.next)

    assert(this.next.calledOnce)
    assert(this.next.calledWithExactly())
    assert(this.res.setHeader.calledWithExactly('Strict-Transport-Security', 'max-age=1235; includeSubDomains'))
  })

  it('can set max-age to -0', function () {
    hsts({
      maxAge: -0
    })(this.req, this.res, this.next)

    assert(this.next.calledOnce)
    assert(this.next.calledWithExactly())
    assert(this.res.setHeader.calledWithExactly('Strict-Transport-Security', 'max-age=0; includeSubDomains'))
  })

  it('can set max-age to 0', function () {
    hsts({
      maxAge: 0
    })(this.req, this.res, this.next)

    assert(this.next.calledOnce)
    assert(this.next.calledWithExactly())
    assert(this.res.setHeader.calledWithExactly('Strict-Transport-Security', 'max-age=0; includeSubDomains'))
  })

  it('can disable subdomains with the includeSubDomains option', function () {
    hsts({
      includeSubDomains: false
    })(this.req, this.res, this.next)

    assert(this.next.calledOnce)
    assert(this.next.calledWithExactly())
    assert(this.res.setHeader.calledWithExactly('Strict-Transport-Security', 'max-age=86400'))
  })

  it('can disable subdomains with the includeSubdomains option', function () {
    hsts({
      includeSubdomains: false
    })(this.req, this.res, this.next)

    assert(this.next.calledOnce)
    assert(this.next.calledWithExactly())
    assert(this.res.setHeader.calledWithExactly('Strict-Transport-Security', 'max-age=86400'))
  })

  it('can enable preloading', function () {
    hsts({
      preload: true
    })(this.req, this.res, this.next)

    assert(this.next.calledOnce)
    assert(this.next.calledWithExactly())
    assert(this.res.setHeader.calledWithExactly('Strict-Transport-Security', 'max-age=86400; includeSubDomains; preload'))
  })

  it('can set the header based on your own condition', function () {
    var options = {
      setIf: function (req) {
        return req.pleaseSet
      }
    }

    hsts(options)({}, this.res, this.next)

    assert(this.next.calledOnce)
    assert(this.next.calledWithExactly())
    assert(!this.res.setHeader.called)

    hsts(options)({ pleaseSet: true }, this.res, this.next)

    assert(this.next.calledTwice)
    assert(this.next.alwaysCalledWithExactly())
    assert(this.res.setHeader.calledWithExactly('Strict-Transport-Security', 'max-age=86400; includeSubDomains'))
  })

  it('can force the header', function () {
    this.req.secure = false

    hsts({
      force: true
    })(this.req, this.res, this.next)

    assert(this.next.calledOnce)
    assert(this.next.calledWithExactly())
    assert(this.res.setHeader.calledWithExactly('Strict-Transport-Security', 'max-age=86400; includeSubDomains'))
  })

  it('names its function and middleware', function () {
    assert.equal(hsts.name, 'hsts')
    assert.equal(hsts().name, 'hsts')
  })
})
