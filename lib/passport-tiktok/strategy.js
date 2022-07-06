'use strict';

var isFunction = require('lodash/isFunction'),
    isObjectLike = require('lodash/isObjectLike'),
    isString = require('lodash/isString'),
    isUndefined = require('lodash/isUndefined'),
    util = require('util'),
    OAuth2Strategy = require('passport-oauth').OAuth2Strategy,
    InternalOAuthError = require('passport-oauth').InternalOAuthError;


/**
 * `Strategy` constructor.
 *
 * The Tiktok authentication strategy authenticates requests by delegating
 * to Tiktok using the OAuth 2.0 protocol as described here:
 * https://developers.tiktok.com/doc/login-kit-web
 *
 * Applications must supply a `verify` callback which accepts an `accessToken`,
 * `refreshToken` and service-specific `profile`, and then calls the `done`
 * callback supplying a `user`, which should be set to `false` if the
 * credentials are not valid.  If an exception occured, `err` should be set.
 *
 * Options:
 *   - `clientID`         your Tiktok application's app id
 *   - `clientSecret`      your Tiktok application's app secret
 *   - `scope`              Scopes allowed for your Tiktok Application
 *   - `callbackURL`        URL to which Tiktok will redirect the user after granting authorization
 *
 * Examples:
 *
 *     var tiktok = require('passport-tiktok');
 *
 *     passport.use(new tiktok.Strategy({
 *         clientID: '123-456-789',
 *         clientSecret: 'shhh-its-a-secret',
 *         scope: ['user.info.basic'],
 *         callbackURL: 'https://www.example.net/auth/tiktok/callback'
 *       },
 *       function(accessToken, refreshToken, profile, done) {
 *         User.findOrCreate(..., function (err, user) {
 *           done(err, user);
 *         });
 *       }
 *     ));
 *
 * @param {Object} options
 * @param {Function} verify
 * @api public
 */
function Strategy(options, verify) {

    if (!isObjectLike(options)) {
        throw new TypeError('Please pass the options.');
    }

    if (!isFunction(verify)) {
        throw new TypeError('Please pass the verify callback.');
    }

    function validateStringOption(optionName) {
        if (!isUndefined(options[optionName]) && (!isString(options[optionName]) || options[optionName].length === 0)) {
            throw new TypeError('Please pass a string to options.' + optionName);
        }
    }

    validateStringOption('authorizationURL');
    validateStringOption('tokenURL');
    validateStringOption('scopeSeparator');
    validateStringOption('sessionKey');
    validateStringOption('profileURL');

    options.authorizationURL = options.authorizationURL || 'https://open-api.tiktok.com/platform/oauth/connect/';
    options.tokenURL = options.tokenURL || 'https://open-api.tiktok.com/oauth/access_token/';
    options.scopeSeparator = options.scopeSeparator || ',';
    options.scope = options.scope || ['user.info.basic'];
    options.sessionKey = options.sessionKey || 'oauth2:tiktok';

    OAuth2Strategy.call(this, options, verify);
    this.name = 'tiktok';
    this._oauth2.useAuthorizationHeaderforGET(true);
    this._profileURL = options.profileURL || 'https://open-api.tiktok.com/user/info/';
    this.options = options;

}

/**
 * Inherit from `OAuth2Strategy`.
 */
util.inherits(Strategy, OAuth2Strategy);


/**
 * Retrieve user profile from Tiktok.
 *
 * This function constructs a normalized profile, with the following properties:
 *
 *   - `provider`         always set to `tiktok`
 *   - `id`               the user's internal Tiktok ID
 *   - `displayName`      the user's full name
 *   - `url`              the user's profile page url
 *
 * @param {String} accessToken
 * @param {Function} done
 * @api protected
 */
Strategy.prototype.userProfile = function(accessToken, authData, done) {

    var url = this._profileURL;
    const params = {
        access_token: accessToken,
        open_id: authData.open_id,
        fields: ["open_id", "union_id", "avatar_url", "avatar_url_100", "avatar_url_200", "avatar_large_url", "display_name"]
    }
    this._oauth2._request("POST", url, {}, JSON.stringify(params), accessToken, function (err, body, res) {

        if (err) {
            return done(new InternalOAuthError('failed to fetch user profile', err));
        }

        try {

            var json = JSON.parse(body);

            var profile = {
                provider: 'tiktok',
                id: json.data.user.open_id,
                unionId: json.data.user.union_id,
                username: json.data.user.display_name,
                profileImage: json.data.user.avatar_url_100,
                displayName: json.data.user.display_name
            };

            profile._raw = body;
            profile._json = json;

            done(null, profile);

        } catch(e) {
            done(e);
        }

    });

};


/**
 * Return extra Tiktok-specific parameters to be included in the
 * authorization request.
 *
 * @param {Object} options
 * @return {Object}
 * @api protected
 */
 Strategy.prototype.authorizationParams = function (options) {
    return {client_key: this.options.clientID};
};


/**
 * Return extra Tiktok-specific parameters to be included in the
 * authorization request.
 *
 * @param {Object} options
 * @return {Object}
 * @api protected
 */
 Strategy.prototype.tokenParams = function (options) {
    return {client_key: this.options.clientID, client_secret: this.options.clientSecret};
};


/**
 * Authenticate request by delegating to a service provider using OAuth 2.0.
 *
 * @param {Object} req
 * @api protected
 */
Strategy.prototype.authenticate = function(req, options) {
	var self = this;

	if (req.query && req.query.error) {
        if (req.query.error == 'access_denied') {
          return this.fail({ message: req.query.error_description });
        } else {
          return this.error(new AuthorizationError(req.query.error_description, req.query.error, req.query.error_uri));
        }
      }

    var callbackURL = options.callbackURL || this._callbackURL;
    var meta = {
        authorizationURL: this._oauth2._authorizeUrl,
        tokenURL: this._oauth2._accessTokenUrl,
        clientID: this._oauth2._clientId,
        callbackURL: callbackURL
    }

	if (req.query && req.query.code){
        function loaded(err, ok, state) {
            if (err) { return self.error(err); }
            if (!ok) {
              return self.fail(state, 403);
            }
      
            var code = req.query.code;
      
            var params = self.tokenParams(options);
            params.grant_type = 'authorization_code';
            if (callbackURL) { params.redirect_uri = callbackURL; }
            if (typeof ok == 'string') { // PKCE
              params.code_verifier = ok;
            }
      
            self._oauth2.getOAuthAccessToken(code, params,
              function(err, accessToken, refreshToken, params) {
                if (params.message === "error") { return self.error(self._createOAuthError('Failed to obtain access token', params.data)); }
                if (!params || !params.data || !params.data.access_token) { return self.error(new Error('Failed to obtain access token')); }
                var authData = params.data;
                accessToken = authData.access_token;
                refreshToken = authData.refresh_token;
                self._loadUserProfile(accessToken, authData, function(err, profile) {
                  if (err) { return self.error(err); }
      
                  function verified(err, user, info) {
                    if (err) { return self.error(err); }
                    if (!user) { return self.fail(info); }
      
                    info = info || {};
                    if (state) { info.state = state; }
                    self.success(user, info);
                  }
      
                  try {
                    if (self._passReqToCallback) {
                      var arity = self._verify.length;
                      if (arity == 6) {
                        self._verify(req, accessToken, refreshToken, params, profile, verified);
                      } else { // arity == 5
                        self._verify(req, accessToken, refreshToken, profile, verified);
                      }
                    } else {
                      var arity = self._verify.length;
                      if (arity == 5) {
                        self._verify(accessToken, refreshToken, params, profile, verified);
                      } else { // arity == 4
                        self._verify(accessToken, refreshToken, profile, verified);
                      }
                    }
                  } catch (ex) {
                    return self.error(ex);
                  }
                });
              }
            );
          }
      
          var state = req.query.state;
          try {
            var arity = self._stateStore.verify.length;
            if (arity == 4) {
              this._stateStore.verify(req, state, meta, loaded);
            } else { // arity == 3
              this._stateStore.verify(req, state, loaded);
            }
          } catch (ex) {
            return this.error(ex);
          }
	} else {
        return OAuth2Strategy.prototype.authenticate.call(this, req, options);
	}
};


/**
 * Load user profile, contingent upon options.
 *
 * @param {String} accessToken
 * @param {Function} done
 * @api private
 */
 Strategy.prototype._loadUserProfile = function(accessToken, paramsData, done) {
    var self = this;
  
    function loadIt() {
      return self.userProfile(accessToken, paramsData, done);
    }
    function skipIt() {
      return done(null);
    }
  
    if (typeof this._skipUserProfile == 'function' && this._skipUserProfile.length > 1) {
      // async
      this._skipUserProfile(accessToken, function(err, skip) {
        if (err) { return done(err); }
        if (!skip) { return loadIt(); }
        return skipIt();
      });
    } else {
      var skip = (typeof this._skipUserProfile == 'function') ? this._skipUserProfile() : this._skipUserProfile;
      if (!skip) { return loadIt(); }
      return skipIt();
    }
  };
/**
 * Expose `Strategy`.
 */
module.exports = Strategy;
