/**
 * ============================================
 *  Easy Auth — Full Example App
 * ============================================
 *
 *  Run:
 *    npm install
 *    node example.js
 *
 *  Test with curl:
 *
 *    # Register
 *    curl -X POST http://localhost:3000/register \
 *      -H "Content-Type: application/json" \
 *      -d '{"username":"rakib","password":"123456"}'
 *
 *    # Login (get JWT token)
 *    curl -X POST http://localhost:3000/login \
 *      -H "Content-Type: application/json" \
 *      -d '{"username":"rakib","password":"123456"}'
 *
 *    # Access protected route
 *    curl http://localhost:3000/profile \
 *      -H "Authorization: Bearer <your-token>"
 *
 *    # Try admin route (will fail — role is 'user')
 *    curl http://localhost:3000/admin \
 *      -H "Authorization: Bearer <your-token>"
 */

const express = require('express');
const {
  EasyAuth,
  LocalStrategy,
  JwtStrategy,
  hashPassword,
  comparePassword,
  generateToken,
} = require('node-easy-auth');  // use './index' if running from source

const app = express();
app.use(express.json());

// ========== Config ==========
const JWT_SECRET = 'change-this-in-production';
const auth = new EasyAuth();

// ========== Fake DB ==========
const users = [];

// ========== Strategies ==========

// Local: for login
auth.use('local', new LocalStrategy(async (username, password, done) => {
  const user = users.find(u => u.username === username);
  if (!user) return done(null, false, { message: 'User not found' });

  const match = await comparePassword(password, user.password);
  if (!match) return done(null, false, { message: 'Wrong password' });

  return done(null, user);
}));

// JWT: for protected API routes
auth.use('jwt', new JwtStrategy(
  { secret: JWT_SECRET, extractFrom: 'header' },
  (payload, done) => {
    const user = users.find(u => u.id === payload.id);
    if (!user) return done(null, false);
    return done(null, user);
  }
));

// ========== Routes ==========

app.post('/register', async (req, res) => {
  const { username, password, role } = req.body;

  if (!username || !password) {
    return res.status(400).json({ error: 'username and password required' });
  }

  if (users.find(u => u.username === username)) {
    return res.status(409).json({ error: 'Username already exists' });
  }

  const hashed = await hashPassword(password);
  const user = {
    id: Date.now().toString(),
    username,
    password: hashed,
    role: role || 'user',
  };
  users.push(user);

  console.log(`✅ Registered: ${username} (role: ${user.role})`);
  res.status(201).json({ success: true, message: 'User registered!' });
});

app.post('/login', auth.authenticate('local'), (req, res) => {
  const token = generateToken(
    { id: req.user.id, username: req.user.username },
    JWT_SECRET,
    { expiresIn: '7d' }
  );

  console.log(`🔑 Login: ${req.user.username}`);
  res.json({ success: true, token });
});

app.get('/profile',
  auth.authenticate('jwt'),
  (req, res) => {
    res.json({
      id: req.user.id,
      username: req.user.username,
      role: req.user.role,
    });
  }
);

app.get('/admin',
  auth.authenticate('jwt'),
  auth.authorize('admin'),
  (req, res) => {
    res.json({ message: `Welcome admin ${req.user.username}!` });
  }
);

app.get('/', (req, res) => {
  res.json({
    message: 'Easy Auth Example API',
    routes: {
      'POST /register': '{ username, password, role? }',
      'POST /login': '{ username, password } → returns JWT token',
      'GET /profile': 'Protected — needs Authorization: Bearer <token>',
      'GET /admin': 'Protected — needs admin role',
    },
  });
});

// ========== Start ==========
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`\n🚀 Easy Auth Example running on http://localhost:${PORT}\n`);
});
