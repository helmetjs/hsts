import { IncomingMessage, ServerResponse } from 'http';

interface HstsOptions {
  maxAge?: number | bigint;
  includeSubDomains?: boolean;
  preload?: boolean;
}

function getMaxAgeValue(maxAge: unknown): number | bigint {
  if (typeof maxAge === 'number') {
    if (maxAge < 0) {
      throw new RangeError('HSTS maxAge must be nonnegative.');
    } else if (Number.isNaN(maxAge)) {
      throw new Error('HSTS maxAge must not be NaN.');
    } else if (!Number.isFinite(maxAge)) {
      throw new Error('HSTS maxAge must be a finite number.');
    } else {
      return Math.round(maxAge);
    }
  } else if (typeof maxAge === 'bigint') {
    if (maxAge < 0) {
      throw new RangeError('HSTS maxAge must be nonnegative.');
    } else {
      return maxAge;
    }
  } else {
    throw new TypeError('HSTS must be passed a numeric maxAge parameter.');
  }
}

function getHeaderValueFromOptions(options: HstsOptions): string {
  const DEFAULT_MAX_AGE = 180 * 24 * 60 * 60;

  if ('maxage' in options) {
    throw new Error('"maxage" is not a supported property. Did you mean to use "maxAge" instead?');
  }
  if ('includeSubdomains' in options) {
    throw new Error('"includeSubdomains" is not a supported property. Did you mean to use "includeSubDomains" instead?');
  }

  const maxAge = 'maxAge' in options ? options.maxAge : DEFAULT_MAX_AGE;
  let header = `max-age=${getMaxAgeValue(maxAge)}`;
  if (options.includeSubDomains !== false) {
    header += '; includeSubDomains';
  }
  if (options.preload) {
    header += '; preload';
  }

  return header;
}

export = function hsts(options: HstsOptions = {}) {
  const headerValue = getHeaderValueFromOptions(options);

  return function hsts(
    _req: IncomingMessage,
    res: ServerResponse,
    next: () => void
  ) {
    res.setHeader('Strict-Transport-Security', headerValue);
    next();
  };
};
