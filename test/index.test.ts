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
    expect(() => hsts({ maxAge: '123' } as any)).toThrow();
    expect(() => hsts({ maxAge: true } as any)).toThrow();
    expect(() => hsts({ maxAge: false } as any)).toThrow();
    expect(() => hsts({ maxAge: {} } as any)).toThrow();
    expect(() => hsts({ maxAge: [] } as any)).toThrow();

    expect(() => hsts({ setIf: 123 } as any)).toThrow();
    expect(() => hsts({ setIf: true } as any)).toThrow();
    expect(() => hsts({ setIf: false } as any)).toThrow();
    expect(() => hsts({ setIf: null } as any)).toThrow();

    expect(() => hsts({ maxage: false } as any)).toThrow();
    expect(() => hsts({ maxage: 1234 } as any)).toThrow();
    expect(() =>
      hsts({
        includeSubDomains: true,
        includeSubdomains: true,
      } as any)).toThrow();
    expect(() =>
      hsts({
        includeSubDomains: false,
        includeSubdomains: true,
      } as any)).toThrow();
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

  it('can disable subdomains with the includeSubDomains option', async () => {
    await request(app(hsts({
      includeSubDomains: false,
    })))
      .get('/')
      .expect('Strict-Transport-Security', 'max-age=15552000');
  });

  it('can disable subdomains with the includeSubdomains option, but a deprecation warning is shown', () => {
    // We can remove this test in hsts@3.
    const deprecationPromise = new Promise(resolve => {
      process.on('deprecation', deprecationError => {
        if (
          deprecationError.message.includes('The "includeSubdomains" parameter is deprecated. Use "includeSubDomains" (with a capital D) instead.')
        ) {
          resolve();
        }
      });
    });

    /* eslint-disable @typescript-eslint/no-explicit-any */
    const supertestPromise = request(app(hsts({
      includeSubdomains: false,
    } as any)))
      .get('/')
      .expect('Strict-Transport-Security', 'max-age=15552000');
    /* eslint-enable @typescript-eslint/no-explicit-any */

    return Promise.all([deprecationPromise, supertestPromise]);
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

  it('can use setIf to conditionally set the header, but it is deprecated', () => {
    // We can remove this test in hsts@3.
    const deprecationPromise = new Promise(resolve => {
      process.on('deprecation', deprecationError => {
        if (
          deprecationError.message.includes('The "setIf" parameter is deprecated. Refer to the documentation to see how to set the header conditionally.')
        ) {
          resolve();
        }
      });
    });

    const server = app(hsts({
      setIf(req) {
        return req.headers['x-should-set'] === 'yes';
      },
    }));

    const shouldntSetPromise = request(server)
      .get('/')
      .set('X-Should-Set', 'no')
      .then((res: any) => {
        expect(res.headers).not.toHaveProperty('strict-transport-security');
      });

    const shouldSetPromise = request(server)
      .get('/')
      .set('X-Should-Set', 'yes')
      .expect(
        'Strict-Transport-Security',
        'max-age=15552000; includeSubDomains'
      );

    return Promise.all([
      deprecationPromise,
      shouldntSetPromise,
      shouldSetPromise,
    ]);
  });

  it('does nothing with the `force` option; allowed for backwards compatibility', async () => {
    // We should remove this test in hsts@3.
    /* eslint-disable @typescript-eslint/no-explicit-any */
    await request(app(hsts({
      force: true,
    } as any)))
      .get('/')
      .expect(
        'Strict-Transport-Security',
        'max-age=15552000; includeSubDomains'
      );
    /* eslint-enable @typescript-eslint/no-explicit-any */
  });

  it('names its function and middleware', () => {
    expect(hsts.name).toStrictEqual('hsts');
    expect(hsts().name).toStrictEqual('hsts');
  });
});
