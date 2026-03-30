/**
 * Basic smoke tests for node-easy-auth
 * Run: node test.js
 */

const assert = require('assert');

async function runTests() {
  console.log('🧪 Running node-easy-auth tests...\n');
  let passed = 0;
  let failed = 0;

  function test(name, fn) {
    return fn()
      .then(() => {
        console.log(`  ✅ ${name}`);
        passed++;
      })
      .catch((err) => {
        console.log(`  ❌ ${name}`);
        console.log(`     ${err.message}`);
        failed++;
      });
  }

  const {
    EasyAuth,
    LocalStrategy,
    JwtStrategy,
    hashPassword,
    comparePassword,
    generateToken,
    verifyToken,
  } = require('./index');

  // ---- Utility Tests ----

  console.log('Utilities:');

  await test('hashPassword returns a hash', async () => {
    const hash = await hashPassword('test123');
    assert(hash, 'Hash should exist');
    assert(hash !== 'test123', 'Hash should differ from plain text');
    assert(hash.startsWith('$2b$'), 'Should be bcrypt hash');
  });

  await test('comparePassword matches correctly', async () => {
    const hash = await hashPassword('mypassword');
    const match = await comparePassword('mypassword', hash);
    assert.strictEqual(match, true, 'Should match');
  });

  await test('comparePassword rejects wrong password', async () => {
    const hash = await hashPassword('mypassword');
    const match = await comparePassword('wrongpassword', hash);
    assert.strictEqual(match, false, 'Should not match');
  });

  await test('generateToken creates valid JWT', async () => {
    const token = generateToken({ id: '123', role: 'admin' }, 'secret');
    assert(token, 'Token should exist');
    assert(token.split('.').length === 3, 'JWT should have 3 parts');
  });

  await test('verifyToken decodes valid token', async () => {
    const token = generateToken({ id: '456' }, 'secret', { expiresIn: '1h' });
    const payload = verifyToken(token, 'secret');
    assert(payload, 'Payload should exist');
    assert.strictEqual(payload.id, '456', 'ID should match');
  });

  await test('verifyToken returns null for invalid token', async () => {
    const result = verifyToken('invalid.token.here', 'secret');
    assert.strictEqual(result, null, 'Should return null');
  });

  await test('verifyToken returns null for wrong secret', async () => {
    const token = generateToken({ id: '789' }, 'secret1');
    const result = verifyToken(token, 'wrong-secret');
    assert.strictEqual(result, null, 'Should return null for wrong secret');
  });

  // ---- Core Tests ----

  console.log('\nEasyAuth Core:');

  await test('EasyAuth initializes correctly', async () => {
    const auth = new EasyAuth();
    assert(auth.strategies, 'Should have strategies object');
  });

  await test('use() registers a strategy', async () => {
    const auth = new EasyAuth();
    const strategy = new LocalStrategy((u, p, done) => done(null, false));
    auth.use('local', strategy);
    assert(auth.strategies.local, 'Strategy should be registered');
  });

  await test('serializeUser / deserializeUser stores functions', async () => {
    const auth = new EasyAuth();
    auth.serializeUser((user, done) => done(null, user.id));
    auth.deserializeUser((id, done) => done(null, { id }));
    assert(auth.serializeFn, 'serializeFn should be set');
    assert(auth.deserializeFn, 'deserializeFn should be set');
  });

  await test('protect() blocks unauthenticated requests', async () => {
    const auth = new EasyAuth();
    const middleware = auth.protect();

    let statusCode;
    let jsonBody;
    const mockReq = {
      isAuthenticated: () => false,
      session: {},
    };
    const mockRes = {
      status(code) { statusCode = code; return this; },
      json(body) { jsonBody = body; },
    };

    middleware(mockReq, mockRes, () => {});
    assert.strictEqual(statusCode, 401, 'Should return 401');
    assert.strictEqual(jsonBody.success, false);
  });

  await test('protect() allows authenticated requests', async () => {
    const auth = new EasyAuth();
    const middleware = auth.protect();

    let nextCalled = false;
    const mockReq = { isAuthenticated: () => true };

    middleware(mockReq, {}, () => { nextCalled = true; });
    assert.strictEqual(nextCalled, true, 'next() should be called');
  });

  await test('authorize() blocks unauthorized roles', async () => {
    const auth = new EasyAuth();
    const middleware = auth.authorize('admin');

    let statusCode;
    let jsonBody;
    const mockReq = {
      isAuthenticated: () => true,
      user: { role: 'user' },
      session: {},
    };
    const mockRes = {
      status(code) { statusCode = code; return this; },
      json(body) { jsonBody = body; },
    };

    middleware(mockReq, mockRes, () => {});
    assert.strictEqual(statusCode, 403, 'Should return 403');
  });

  await test('authorize() allows correct roles', async () => {
    const auth = new EasyAuth();
    const middleware = auth.authorize('admin', 'moderator');

    let nextCalled = false;
    const mockReq = {
      isAuthenticated: () => true,
      user: { role: 'admin' },
    };

    middleware(mockReq, {}, () => { nextCalled = true; });
    assert.strictEqual(nextCalled, true, 'next() should be called for admin');
  });

  // ---- Strategy Tests ----

  console.log('\nStrategies:');

  await test('LocalStrategy authenticates valid credentials', async () => {
    const hash = await hashPassword('pass123');
    const users = [{ id: '1', username: 'john', password: hash }];

    const strategy = new LocalStrategy(async (username, password, done) => {
      const user = users.find((u) => u.username === username);
      if (!user) return done(null, false);
      const match = await comparePassword(password, user.password);
      if (!match) return done(null, false);
      return done(null, user);
    });

    return new Promise((resolve, reject) => {
      strategy.authenticate(
        { body: { username: 'john', password: 'pass123' } },
        (err, user) => {
          if (err) return reject(err);
          assert(user, 'User should be returned');
          assert.strictEqual(user.username, 'john');
          resolve();
        }
      );
    });
  });

  await test('LocalStrategy rejects wrong password', async () => {
    const hash = await hashPassword('pass123');
    const users = [{ id: '1', username: 'john', password: hash }];

    const strategy = new LocalStrategy(async (username, password, done) => {
      const user = users.find((u) => u.username === username);
      if (!user) return done(null, false);
      const match = await comparePassword(password, user.password);
      if (!match) return done(null, false, { message: 'Wrong' });
      return done(null, user);
    });

    return new Promise((resolve, reject) => {
      strategy.authenticate(
        { body: { username: 'john', password: 'wrongpass' } },
        (err, user) => {
          if (err) return reject(err);
          assert.strictEqual(user, false, 'Should return false');
          resolve();
        }
      );
    });
  });

  await test('LocalStrategy supports custom fields', async () => {
    const strategy = new LocalStrategy(
      { usernameField: 'email', passwordField: 'pass' },
      async (email, pass, done) => {
        assert.strictEqual(email, 'test@mail.com');
        assert.strictEqual(pass, 'abc');
        done(null, { email });
      }
    );

    return new Promise((resolve) => {
      strategy.authenticate(
        { body: { email: 'test@mail.com', pass: 'abc' } },
        (err, user) => {
          assert(user, 'User should exist');
          resolve();
        }
      );
    });
  });

  await test('JwtStrategy validates token from header', async () => {
    const token = generateToken({ id: '99' }, 'test-secret');

    const strategy = new JwtStrategy(
      { secret: 'test-secret', extractFrom: 'header' },
      (payload, done) => {
        done(null, { id: payload.id });
      }
    );

    return new Promise((resolve) => {
      strategy.authenticate(
        { headers: { authorization: `Bearer ${token}` }, query: {}, cookies: {} },
        (err, user) => {
          assert(user, 'User should exist');
          assert.strictEqual(user.id, '99');
          resolve();
        }
      );
    });
  });

  await test('JwtStrategy rejects invalid token', async () => {
    const strategy = new JwtStrategy(
      { secret: 'test-secret' },
      (payload, done) => done(null, { id: payload.id })
    );

    return new Promise((resolve) => {
      strategy.authenticate(
        { headers: { authorization: 'Bearer fake.token.here' }, query: {}, cookies: {} },
        (err, user, info) => {
          assert.strictEqual(user, false);
          resolve();
        }
      );
    });
  });

  // ---- Summary ----
  console.log(`\n${'='.repeat(40)}`);
  console.log(`  Total: ${passed + failed} | ✅ Passed: ${passed} | ❌ Failed: ${failed}`);
  console.log(`${'='.repeat(40)}\n`);

  if (failed > 0) process.exit(1);
}

runTests().catch(console.error);
