/**
 * LocalStrategy — Username + Password authentication
 *
 * Usage:
 *   const { LocalStrategy } = require('easy-auth');
 *
 *   auth.use('local', new LocalStrategy(async (username, password, done) => {
 *     const user = await User.findOne({ username });
 *     if (!user) return done(null, false, { message: 'User not found' });
 *
 *     const match = await comparePassword(password, user.password);
 *     if (!match) return done(null, false, { message: 'Wrong password' });
 *
 *     return done(null, user);
 *   }));
 */

class LocalStrategy {
  /**
   * @param {object} options - { usernameField, passwordField } (optional)
   * @param {function} verify - (username, password, done) => {}
   */
  constructor(options, verify) {
    if (typeof options === 'function') {
      verify = options;
      options = {};
    }

    this.name = 'local';
    this.usernameField = options.usernameField || 'username';
    this.passwordField = options.passwordField || 'password';
    this.verify = verify;
  }

  authenticate(req, done) {
    const username = req.body?.[this.usernameField];
    const password = req.body?.[this.passwordField];

    if (!username || !password) {
      return done(null, false, {
        message: `Missing ${this.usernameField} or ${this.passwordField}`,
      });
    }

    try {
      this.verify(username, password, done);
    } catch (err) {
      done(err);
    }
  }
}

module.exports = LocalStrategy;
