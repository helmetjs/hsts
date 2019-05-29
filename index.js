var DEFAULT_MAX_AGE = 180 * 24 * 60 * 60

module.exports = function hsts (options) {
  options = options || {}

  var maxAge = options.maxAge != null ? options.maxAge : DEFAULT_MAX_AGE
  var includeSubDomains = options.includeSubDomains !== false

  if (options.hasOwnProperty('maxage')) {
    throw new Error('maxage is not a supported property. Did you mean to pass "maxAge" instead of "maxage"?')
  }
  if (arguments.length > 1) {
    throw new Error('HSTS passed the wrong number of arguments.')
  }
  if (typeof maxAge !== 'number') {
    throw new TypeError('HSTS must be passed a numeric maxAge parameter.')
  }
  if (maxAge < 0) {
    throw new RangeError('HSTS maxAge must be nonnegative.')
  }

  var header = 'max-age=' + Math.round(maxAge)
  if (includeSubDomains) {
    header += '; includeSubDomains'
  }
  if (options.preload) {
    header += '; preload'
  }

  return function hsts (req, res, next) {
    res.setHeader('Strict-Transport-Security', header)
    next()
  }
}
