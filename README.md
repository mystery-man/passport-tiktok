# Passport-Tiktok

[Passport](https://github.com/jaredhanson/passport) strategy for authenticating with [Tiktok](https://www.tiktok.com) using the OAuth 2.0 API.

This module lets you authenticate using Tiktok in your Node.js applications. By plugging into Passport, Tiktok authentication can be easily and unobtrusively integrated into any application or framework that supports [Connect](http://www.senchalabs.org/connect/)-style middleware, including [Express](http://expressjs.com/).

## Installation

[![NPM Stats](https://nodei.co/npm/passport-tiktok-auth.png?downloads=true)](https://npmjs.org/package/passport-tiktok-auth)

This is a module for node.js and is installed via npm:

``` bash
npm install passport-tiktok-auth --save
```

## Usage

### Configure Strategy

The Tiktok authentication strategy authenticates users using a Tiktok account and OAuth 2.0 tokens. The strategy requires a `verify` callback, which accepts these credentials and calls `done` providing a user, as well as `options` specifying a client ID, client secret, scope, and callback URL.

``` js
passport.use(new TiktokStrategy({
        clientID: TIKTOK_CLIENT_ID,
        clientSecret: TIKTOK_CLIENT_SECRET,
        scope: ['user.info.basic'],
        callbackURL: "https://localhost:3000/auth/tiktok/callback"
    },
    function(accessToken, refreshToken, profile, done) {
        User.findOrCreate({ tiktokId: profile.id }, function (err, user) {
            return done(err, user);
        });
    }
));
```

**Tiktok only allows https callback urls.** [This blog article](http://blog.mgechev.com/2014/02/19/create-https-tls-ssl-application-with-express-nodejs/) explains the quickest way to enable https for your Express server.

### Authenticate Requests

Use `passport.authenticate()`, specifying the `'tiktok'` strategy, to authenticate requests.

For example, as route middleware in an [Express](http://expressjs.com/) application:

``` js
app.get('/auth/tiktok',
    passport.authenticate('tiktok')
);

app.get('/auth/tiktok/callback', 
    passport.authenticate('tiktok', { failureRedirect: '/login' }),
    function(req, res) {
        // Successful authentication, redirect home.
        res.redirect('/');
    }
);
```

## License (ISC)

In case you never heard about the [ISC license](http://en.wikipedia.org/wiki/ISC_license) it is functionally equivalent to the MIT license.

See the [LICENSE file](LICENSE) for details.
