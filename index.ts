import { IncomingMessage, ServerResponse } from 'http';

interface HstsOptions {
  includeSubDomains?: boolean;
  maxAge?: number | null;
  preload?: boolean;
}

function getHeaderValueFromOptions(options: HstsOptions): string {
  const DEFAULT_MAX_AGE = 180 * 24 * 60 * 60;

  if ('maxage' in options) {
    throw new Error('maxage is not a supported property. Did you mean to pass "maxAge" instead of "maxage"?');
  }

  const maxAge = 'maxAge' in options ? options.maxAge : DEFAULT_MAX_AGE;
  if (typeof maxAge !== 'number') {
    throw new TypeError('HSTS must be passed a numeric maxAge parameter.');
  } else if (maxAge < 0) {
    throw new RangeError('HSTS maxAge must be nonnegative.');
  }

  let header = `max-age=${Math.round(maxAge)}`;
  if (options.includeSubDomains !== false) {
    header += '; includeSubDomains';
  }
  if (options.preload) {
    header += '; preload';
  }

  return header;
}

export = function hsts (options: HstsOptions = {}) {
  const headerValue = getHeaderValueFromOptions(options);

  return function hsts (_req: IncomingMessage, res: ServerResponse, next: () => void) {
    res.setHeader('Strict-Transport-Security', headerValue);
    next();
  };
}
