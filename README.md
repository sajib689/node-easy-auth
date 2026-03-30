# node-easy-auth

[![npm version](https://img.shields.io/npm/v/node-easy-auth.svg)](https://www.npmjs.com/package/node-easy-auth)
[![license](https://img.shields.io/npm/l/node-easy-auth.svg)](https://github.com/sajib689/node-easy-auth/blob/main/LICENSE)
[![node](https://img.shields.io/node/v/node-easy-auth.svg)](https://nodejs.org)

A lightweight, Passport.js-inspired authentication library for Express.js.

Simple API. Built-in strategies. No bloat.

## Why node-easy-auth?

| | Passport.js | node-easy-auth |
|---|---|---|
| Setup complexity | High (many moving parts) | Minimal (one class) |
| Built-in strategies | Separate packages | Local, JWT, Google included |
| Password hashing | Not included | `hashPassword` / `comparePassword` built-in |
| JWT helpers | Not included | `generateToken` / `verifyToken` built-in |
| Role-based auth | Manual | `authorize('admin')` one-liner |
| TypeScript | Community types | Built-in type definitions |
| Dependencies | Varies by strategy | Only 3 (bcrypt, jsonwebtoken, express-session) |

## Installation

```bash
npm install node-easy-auth
```

## Quick Start — Local Auth (Session-based)

```js
const express = require('express');
const {
  EasyAuth,
  LocalStrategy,
  hashPassword,
  comparePassword,
} = require('node-easy-auth');

const app = express();
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

const auth = new EasyAuth();

// -- Fake DB (replace with MongoDB/Postgres) --
const users = [];

// -- Setup Strategy --
auth.use(
  'local',
  new LocalStrategy(async (username, password, done) => {
    const user = users.find((u) => u.username === username);
    if (!user) return done(null, false, { message: 'User not found' });

    const match = await comparePassword(password, user.password);
    if (!match) return done(null, false, { message: 'Wrong password' });

    return done(null, user);
  })
);

// -- Serialize / Deserialize --
auth.serializeUser((user, done) => done(null, user.id));
auth.deserializeUser((id, done) => {
  const user = users.find((u) => u.id === id);
  done(null, user || null);
});

// -- Initialize --
app.use(auth.initialize({ secret: 'super-secret-key' }));

// -- Routes --
app.post('/register', async (req, res) => {
  const { username, password } = req.body;
  const hashed = await hashPassword(password);
  const user = { id: Date.now().toString(), username, password: hashed };
  users.push(user);
  res.json({ success: true, message: 'Registered!' });
});

app.post('/login', auth.authenticate('local'), (req, res) => {
  res.json({ success: true, user: req.user.username });
});

app.get('/dashboard', auth.protect(), (req, res) => {
  res.json({ message: `Welcome ${req.user.username}!` });
});

app.post('/logout', (req, res) => {
  req.logout(() => res.json({ success: true }));
});

app.listen(3000, () => console.log('Running on :3000'));
```

## JWT Auth (Stateless API)

```js
const {
  EasyAuth,
  LocalStrategy,
  JwtStrategy,
  hashPassword,
  comparePassword,
  generateToken,
} = require('node-easy-auth');

const auth = new EasyAuth();
const JWT_SECRET = 'my-jwt-secret';

// Local strategy — for /login
auth.use(
  'local',
  new LocalStrategy(async (username, password, done) => {
    const user = users.find((u) => u.username === username);
    if (!user) return done(null, false);
    const match = await comparePassword(password, user.password);
    if (!match) return done(null, false);
    return done(null, user);
  })
);

// JWT strategy — for protected routes
auth.use(
  'jwt',
  new JwtStrategy(
    { secret: JWT_SECRET, extractFrom: 'header' },
    async (payload, done) => {
      const user = users.find((u) => u.id === payload.id);
      if (!user) return done(null, false);
      return done(null, user);
    }
  )
);

// Login → return token
app.post('/login', auth.authenticate('local'), (req, res) => {
  const token = generateToken({ id: req.user.id }, JWT_SECRET, {
    expiresIn: '7d',
  });
  res.json({ token });
});

// Protected route → needs "Authorization: Bearer <token>"
app.get('/profile', auth.authenticate('jwt'), (req, res) => {
  res.json({ user: req.user });
});

// Admin only
app.get('/admin', auth.authenticate('jwt'), auth.authorize('admin'), (req, res) => {
  res.json({ message: 'Admin area' });
});
```

## Google OAuth

```js
const { EasyAuth, GoogleStrategy } = require('node-easy-auth');

const auth = new EasyAuth();

auth.use(
  'google',
  new GoogleStrategy(
    {
      clientID: process.env.GOOGLE_CLIENT_ID,
      clientSecret: process.env.GOOGLE_CLIENT_SECRET,
      callbackURL: 'http://localhost:3000/auth/google/callback',
    },
    async (accessToken, refreshToken, profile, done) => {
      let user = await User.findOne({ googleId: profile.id });
      if (!user) {
        user = await User.create({
          googleId: profile.id,
          name: profile.displayName,
          email: profile.email,
          avatar: profile.picture,
        });
      }
      return done(null, user);
    }
  )
);

// Redirect to Google
app.get('/auth/google', auth.strategies.google.redirectMiddleware());

// Handle callback
app.get(
  '/auth/google/callback',
  auth.authenticate('google', {
    successRedirect: '/dashboard',
    failureRedirect: '/login',
  })
);
```

## Custom Login Fields

```js
// Use "email" instead of "username"
auth.use(
  'local',
  new LocalStrategy(
    { usernameField: 'email', passwordField: 'password' },
    async (email, password, done) => {
      const user = await User.findOne({ email });
      // ...
    }
  )
);
```

## JWT Extract Locations

```js
// From Authorization header (default)
new JwtStrategy({ secret, extractFrom: 'header' }, verify);

// From cookie
new JwtStrategy({ secret, extractFrom: 'cookie', cookieName: 'auth_token' }, verify);

// From query string  (?token=xxx)
new JwtStrategy({ secret, extractFrom: 'query', queryParam: 'token' }, verify);
```

## API Reference

### `EasyAuth`

| Method | Description |
| --- | --- |
| `use(name, strategy)` | Register a strategy |
| `serializeUser(fn)` | Define session serialization |
| `deserializeUser(fn)` | Define session deserialization |
| `initialize(options)` | Returns session + user middleware |
| `authenticate(name, opts)` | Auth middleware for a strategy |
| `protect(opts)` | Guard — login required |
| `authorize(...roles)` | Guard — specific roles required |

### Strategies

| Strategy | Auth Method |
| --- | --- |
| `LocalStrategy` | Username + Password |
| `JwtStrategy` | Bearer Token / Cookie / Query |
| `GoogleStrategy` | Google OAuth 2.0 |

### Utility Helpers

| Function | Description |
| --- | --- |
| `hashPassword(password, rounds?)` | Bcrypt hash (default 12 rounds) |
| `comparePassword(plain, hash)` | Compare with bcrypt |
| `generateToken(payload, secret, opts)` | Create JWT |
| `verifyToken(token, secret)` | Verify + decode JWT |

## TypeScript

Built-in type definitions included — no `@types` package needed.

```ts
import { EasyAuth, LocalStrategy, JwtStrategy, hashPassword } from 'node-easy-auth';
```

## Contributing

1. Fork it
2. Create your feature branch (`git checkout -b feature/my-feature`)
3. Commit your changes (`git commit -m 'Add my feature'`)
4. Push to the branch (`git push origin feature/my-feature`)
5. Open a Pull Request

## License

[MIT](LICENSE)
