const User = require('../models/user');
const jwt = require('jwt-simple');
const config = require('../config');

function tokenForUser(user) {
  const timestamp = new Date().getTime();
  //iat - issued at time
  //sub - subject
  return jwt.encode({ sub: user.id, iat: timestamp }, config.secret);
}

exports.signin = function(req, res, next) {
  // User has already had their email and password auth'd
  // We just need to give them a token
  res.send({ token: tokenForUser(req.user)} );
}

exports.signup = function(req, res, next) {
  // access data from the body of the request - req.body
  const email = req.body.email;
  const password = req.body.password;

  if (!email || !password) {
    return res.status(422).send({ error: "You must provide and email and password"});
  }

  // Loop through all the records
  User.findOne({ email: email }, function(err, existingUser) {
    if (err) { return next(err); } // error first callbacks

    // See if a user with a given email exists.
    if (existingUser) {
      return res.status(422).send({ error: 'Email is in use' }); // unprocessable entity. Data supplied was bad. User already exists
    }

    // If a user with email DOES exist, return an error. This is signup, not login.
    // creates the user but doesn't save it!
    const user = new User({
      email: email, password: password
    });

    user.save(function(err) {
      if (err) { return next(err) }
      // Respond to request indicating the user was created
      res.json({ token: tokenForUser(user) });
    });
  });
}
