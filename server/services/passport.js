const passport = require('passport');
const User = require('../models/user');
const config = require('../config');
const JwtStategy = require('passport-jwt').Strategy;
const ExtractJwt = require('passport-jwt').ExtractJwt;
const LocalStrategy = require('passport-local');


// Strategy is a method of authentication (facebook, google, password/user, etc.)
// setup options for jwt strategy
const jwtOptions = {
  // where can the strategy find the token. Where is it located?
  jwtFromRequest: ExtractJwt.fromHeader('authorization'),
  secretOrKey: config.secret
};

// create jwt strategy
const jwtLogin = new JwtStategy(jwtOptions, function(payload, done) {
  // See if the user ID and the payload exists in the database
  // If it does, call 'done' with that other
  // Othwerwise, call 'done' without a user object
  User.findById(payload.sub, function(err, user) {
    if (err) { return done(err, false) }; //false because we didnt find a user.
    if (user) {
      // null takes the place of the error, meaning there's no error. :)
      done(null, user);
    } else {
      // user not found - false
      done(null, false);
    }
  })
});

// Create local Strategy
const localOptions = {
  // where to look for the email
  // because we're not using a username, like what passport is expecting
  // we need to specify where to look for
  // password is handled automatically
  usernameField: 'email'
}
const localLogin = new LocalStrategy(localOptions, function(email, password, done) {
  // Verify this username and password, call DONE with the user ->
  // if it is the correct username and password
  // otherwise, call done with false
  User.findOne({ email: email}, function(err, user) {
    // if there was an error, like connection error
    if (err) { return done(err); }
    // if there was no error, but the user doesn't exist
    if (!user) { return done(null, false); }
    // compare password - is 'password' equal to user.password?
    // remember that the password in the DB is encrypted and salted! ->
    // salt + plain password = salt + hashed password
    // password supplied is just a string
    // we're going to encrypt the supplied password and see if their tokens ->
    // match at the end. We never de-crypt passwords.

    user.comparePassword(password, function(err, isMatch) {
      if (err) { return done(err); }
      if (!isMatch) { return done(null, false); }

      // success
      return done(null, user);
    });
  });
});

// Tell passport to use this strategy
passport.use(jwtLogin);
passport.use(localLogin);
