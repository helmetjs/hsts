import connect from 'connect';
import request from 'supertest';
import { IncomingMessage, ServerResponse } from 'http';

import hsts = require('..');

describe('hsts', () => {
  function app(middleware: ReturnType<typeof hsts>) {
    const result = connect();
    result.use(middleware);
    result.use((_req: IncomingMessage, res: ServerResponse) => {
      res.end('Hello world!');
    });
    return result;
  }

  it('throws an error with invalid parameters', () => {
    /* eslint-disable @typescript-eslint/no-explicit-any */
    expect(() => hsts({ maxAge: -123 })).toThrow();
    expect(() => hsts({ maxAge: BigInt(-123) })).toThrow();
    expect(() => hsts({ maxAge: -0.1 })).toThrow();
    expect(() => hsts({ maxAge: Infinity })).toThrow();
    expect(() => hsts({ maxAge: -Infinity })).toThrow();
    expect(() => hsts({ maxAge: NaN })).toThrow();

    expect(() => hsts({ maxAge: '123' } as any)).toThrow();
    expect(() => hsts({ maxAge: true } as any)).toThrow();
    expect(() => hsts({ maxAge: false } as any)).toThrow();
    expect(() => hsts({ maxAge: {} } as any)).toThrow();
    expect(() => hsts({ maxAge: [] } as any)).toThrow();
    expect(() => hsts({ maxAge: null } as any)).toThrow();
    expect(() => hsts({ maxAge: undefined } as any)).toThrow();

    expect(() => hsts({ maxage: false } as any)).toThrow();
    expect(() => hsts({ maxage: 1234 } as any)).toThrow();

    expect(() => hsts({ includeSubdomains: false } as any)).toThrow();
    expect(() => hsts({ includeSubdomains: true } as any)).toThrow();
    /* eslint-enable @typescript-eslint/no-explicit-any */
  });

  it('by default, sets max-age to 180 days and adds "includeSubDomains"', async () => {
    expect(15552000).toStrictEqual(180 * 24 * 60 * 60);

    await request(app(hsts()))
      .get('/')
      .expect(
        'Strict-Transport-Security',
        'max-age=15552000; includeSubDomains'
      );
  });

  it('can set max-age to a positive integer', async () => {
    await request(app(hsts({
      maxAge: 1234,
    })))
      .get('/')
      .expect('Strict-Transport-Security', 'max-age=1234; includeSubDomains');
  });

  it('rounds the max-age', async () => {
    await request(app(hsts({
      maxAge: 1234.56,
    })))
      .get('/')
      .expect('Strict-Transport-Security', 'max-age=1235; includeSubDomains');

    await request(app(hsts({
      maxAge: 1234.49,
    })))
      .get('/')
      .expect('Strict-Transport-Security', 'max-age=1234; includeSubDomains');
  });

  it('can set max-age to -0', async () => {
    await request(app(hsts({
      maxAge: -0,
    })))
      .get('/')
      .expect('Strict-Transport-Security', 'max-age=0; includeSubDomains');
  });

  it('can set max-age to 0', async () => {
    await request(app(hsts({
      maxAge: 0,
    })))
      .get('/')
      .expect('Strict-Transport-Security', 'max-age=0; includeSubDomains');
  });

  it('can set max-age to a bigint', async () => {
    await request(app(hsts({
      maxAge: BigInt(1234),
    })))
      .get('/')
      .expect('Strict-Transport-Security', 'max-age=1234; includeSubDomains');
  });

  it('can disable subdomains with the includeSubDomains option', async () => {
    await request(app(hsts({
      includeSubDomains: false,
    })))
      .get('/')
      .expect('Strict-Transport-Security', 'max-age=15552000');
  });

  it('can enable preloading', async () => {
    await request(app(hsts({
      preload: true,
    })))
      .get('/')
      .expect(
        'Strict-Transport-Security',
        'max-age=15552000; includeSubDomains; preload'
      );
  });

  it('names its function and middleware', () => {
    expect(hsts.name).toStrictEqual('hsts');
    expect(hsts().name).toStrictEqual('hsts');
  });
});
