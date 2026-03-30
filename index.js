const session = require('express-session');
const crypto = require('crypto');

class EasyAuth {
  constructor() {
    this.strategies = {};
    this.serializeFn = null;
    this.deserializeFn = null;
  }

  // ========== Strategy Management ==========

  /**
   * Register a strategy
   * @param {string} name - Strategy name (e.g., 'local', 'jwt')
   * @param {object} strategy - Strategy instance
   */
  use(name, strategy) {
    if (typeof name === 'object') {
      strategy = name;
      name = strategy.name || 'default';
    }
    this.strategies[name] = strategy;
    return this;
  }

  /**
   * Define how to store user in session
   * @param {function} fn - (user, done) => done(null, user.id)
   */
  serializeUser(fn) {
    this.serializeFn = fn;
    return this;
  }

  /**
   * Define how to retrieve user from session
   * @param {function} fn - (id, done) => done(null, user)
   */
  deserializeUser(fn) {
    this.deserializeFn = fn;
    return this;
  }

  // ========== Middleware ==========

  /**
   * Initialize EasyAuth — call app.use(auth.initialize())
   * Sets up session middleware + attaches user to req
   */
  initialize(sessionOptions = {}) {
    const self = this;

    const sessionMiddleware = session({
      secret: sessionOptions.secret || crypto.randomBytes(32).toString('hex'),
      resave: sessionOptions.resave ?? false,
      saveUninitialized: sessionOptions.saveUninitialized ?? false,
      cookie: {
        secure: sessionOptions.secure ?? false,
        httpOnly: sessionOptions.httpOnly ?? true,
        maxAge: sessionOptions.maxAge ?? 24 * 60 * 60 * 1000, // 1 day default
        ...sessionOptions.cookie,
      },
      store: sessionOptions.store || undefined,
    });

    return [
      sessionMiddleware,
      (req, res, next) => {
        // Attach helper methods to req
        req.isAuthenticated = () => !!req.session?.userId;
        req.logout = (cb) => {
          req.session.destroy((err) => {
            req.user = null;
            if (cb) cb(err);
          });
        };

        // Deserialize user from session
        if (req.session?.userId && self.deserializeFn) {
          self.deserializeFn(req.session.userId, (err, user) => {
            if (err) return next(err);
            req.user = user || null;
            next();
          });
        } else {
          req.user = null;
          next();
        }
      },
    ];
  }

  /**
   * Authenticate using a specific strategy
   * @param {string} strategyName
   * @param {object} options - { successRedirect, failureRedirect, failureMessage }
   */
  authenticate(strategyName, options = {}) {
    const self = this;

    return (req, res, next) => {
      const strategy = self.strategies[strategyName];
      if (!strategy) {
        return next(new Error(`Strategy "${strategyName}" is not registered.`));
      }

      strategy.authenticate(req, (err, user, info) => {
        if (err) return next(err);

        // Authentication failed
        if (!user) {
          if (options.failureRedirect) {
            return res.redirect(options.failureRedirect);
          }
          return res.status(401).json({
            success: false,
            message: info?.message || 'Authentication failed',
          });
        }

        // Authentication succeeded — serialize user into session
        if (self.serializeFn) {
          self.serializeFn(user, (err, userId) => {
            if (err) return next(err);
            req.session.userId = userId;
            req.user = user;
            if (options.successRedirect) {
              return res.redirect(options.successRedirect);
            }
            next();
          });
        } else {
          req.session.userId = user.id || user._id;
          req.user = user;
          if (options.successRedirect) {
            return res.redirect(options.successRedirect);
          }
          next();
        }
      });
    };
  }

  // ========== Route Guards ==========

  /**
   * Middleware to protect routes — only logged-in users allowed
   */
  protect(options = {}) {
    return (req, res, next) => {
      if (req.isAuthenticated()) return next();

      if (options.redirect) return res.redirect(options.redirect);

      res.status(401).json({
        success: false,
        message: options.message || 'Please login first',
      });
    };
  }

  /**
   * Role-based access control
   * @param  {...string} roles - Allowed roles
   */
  authorize(...roles) {
    return (req, res, next) => {
      if (!req.isAuthenticated()) {
        return res.status(401).json({
          success: false,
          message: 'Please login first',
        });
      }

      const userRole = req.user?.role || req.user?.type || 'user';
      if (!roles.includes(userRole)) {
        return res.status(403).json({
          success: false,
          message: 'You do not have permission to access this',
        });
      }

      next();
    };
  }
}

// ========== Built-in Strategies ==========

const LocalStrategy = require('./strategies/local');
const JwtStrategy = require('./strategies/jwt');
const GoogleStrategy = require('./strategies/google');

// ========== Utility Helpers ==========

const { hashPassword, comparePassword, generateToken, verifyToken } = require('./utils');

module.exports = {
  EasyAuth,
  LocalStrategy,
  JwtStrategy,
  GoogleStrategy,
  hashPassword,
  comparePassword,
  generateToken,
  verifyToken,
};
