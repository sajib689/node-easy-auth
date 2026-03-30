/**
 * JwtStrategy — JSON Web Token authentication
 *
 * Usage:
 *   const { JwtStrategy } = require('easy-auth');
 *
 *   auth.use('jwt', new JwtStrategy({
 *     secret: 'my-secret-key',
 *     extractFrom: 'header'   // 'header' | 'cookie' | 'query'
 *   }, async (payload, done) => {
 *     const user = await User.findById(payload.id);
 *     if (!user) return done(null, false);
 *     return done(null, user);
 *   }));
 */

const jwt = require('jsonwebtoken');

class JwtStrategy {
  /**
   * @param {object} options - { secret, extractFrom, cookieName, queryParam, headerScheme }
   * @param {function} verify - (payload, done) => {}
   */
  constructor(options, verify) {
    if (!options.secret) {
      throw new Error('JwtStrategy requires a "secret" option');
    }

    this.name = 'jwt';
    this.secret = options.secret;
    this.extractFrom = options.extractFrom || 'header';
    this.cookieName = options.cookieName || 'token';
    this.queryParam = options.queryParam || 'token';
    this.headerScheme = options.headerScheme || 'Bearer';
    this.verify = verify;
  }

  /**
   * Extract JWT token from the request
   */
  extractToken(req) {
    switch (this.extractFrom) {
      case 'header': {
        const authHeader = req.headers?.authorization || '';
        if (authHeader.startsWith(this.headerScheme + ' ')) {
          return authHeader.slice(this.headerScheme.length + 1);
        }
        return null;
      }

      case 'cookie': {
        return req.cookies?.[this.cookieName] || null;
      }

      case 'query': {
        return req.query?.[this.queryParam] || null;
      }

      default:
        return null;
    }
  }

  authenticate(req, done) {
    const token = this.extractToken(req);

    if (!token) {
      return done(null, false, { message: 'No token provided' });
    }

    try {
      const payload = jwt.verify(token, this.secret);
      this.verify(payload, done);
    } catch (err) {
      if (err.name === 'TokenExpiredError') {
        return done(null, false, { message: 'Token expired' });
      }
      if (err.name === 'JsonWebTokenError') {
        return done(null, false, { message: 'Invalid token' });
      }
      done(err);
    }
  }
}

module.exports = JwtStrategy;
