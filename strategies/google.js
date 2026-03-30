/**
 * GoogleStrategy — Google OAuth 2.0 authentication
 *
 * Usage:
 *   const { GoogleStrategy } = require('easy-auth');
 *
 *   auth.use('google', new GoogleStrategy({
 *     clientID: 'GOOGLE_CLIENT_ID',
 *     clientSecret: 'GOOGLE_CLIENT_SECRET',
 *     callbackURL: 'http://localhost:3000/auth/google/callback',
 *   }, async (accessToken, refreshToken, profile, done) => {
 *     let user = await User.findOne({ googleId: profile.id });
 *     if (!user) {
 *       user = await User.create({
 *         googleId: profile.id,
 *         name: profile.displayName,
 *         email: profile.email,
 *       });
 *     }
 *     return done(null, user);
 *   }));
 *
 *   // Routes:
 *   app.get('/auth/google', auth.redirectToGoogle());
 *   app.get('/auth/google/callback', auth.authenticate('google', { ... }));
 */

const crypto = require('crypto');

class GoogleStrategy {
  constructor(options, verify) {
    if (!options.clientID || !options.clientSecret || !options.callbackURL) {
      throw new Error('GoogleStrategy requires clientID, clientSecret, and callbackURL');
    }

    this.name = 'google';
    this.clientID = options.clientID;
    this.clientSecret = options.clientSecret;
    this.callbackURL = options.callbackURL;
    this.scope = options.scope || ['openid', 'profile', 'email'];
    this.verify = verify;
  }

  /**
   * Returns middleware that redirects user to Google consent screen
   */
  redirectMiddleware() {
    const self = this;
    return (req, res) => {
      const state = crypto.randomBytes(16).toString('hex');
      req.session.oauthState = state;

      const params = new URLSearchParams({
        client_id: self.clientID,
        redirect_uri: self.callbackURL,
        response_type: 'code',
        scope: self.scope.join(' '),
        state,
        access_type: 'offline',
        prompt: 'consent',
      });

      res.redirect(`https://accounts.google.com/o/oauth2/v2/auth?${params}`);
    };
  }

  /**
   * Handle callback — exchange code for tokens, fetch profile
   */
  async authenticate(req, done) {
    const { code, state } = req.query || {};

    // Verify state to prevent CSRF
    if (state !== req.session?.oauthState) {
      return done(null, false, { message: 'Invalid OAuth state' });
    }

    if (!code) {
      return done(null, false, { message: 'No authorization code received' });
    }

    try {
      // Exchange code for tokens
      const tokenRes = await fetch('https://oauth2.googleapis.com/token', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          code,
          client_id: this.clientID,
          client_secret: this.clientSecret,
          redirect_uri: this.callbackURL,
          grant_type: 'authorization_code',
        }),
      });

      const tokenData = await tokenRes.json();

      if (tokenData.error) {
        return done(null, false, { message: tokenData.error_description || 'Token exchange failed' });
      }

      // Fetch user profile
      const profileRes = await fetch('https://www.googleapis.com/oauth2/v2/userinfo', {
        headers: { Authorization: `Bearer ${tokenData.access_token}` },
      });

      const profileData = await profileRes.json();

      const profile = {
        id: profileData.id,
        displayName: profileData.name,
        email: profileData.email,
        picture: profileData.picture,
        raw: profileData,
      };

      // Call user's verify callback
      this.verify(tokenData.access_token, tokenData.refresh_token, profile, done);
    } catch (err) {
      done(err);
    }
  }
}

module.exports = GoogleStrategy;
