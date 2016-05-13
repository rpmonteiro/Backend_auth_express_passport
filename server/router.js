const Authentication = require('./controllers/authentication');
const passportService = require('./services/passport');
const passport = require('passport');

// don't create a cookie based session hence the session: false
// we're doing token stuff, not cookie
const requireAuth = passport.authenticate('jwt', { session: false} );
const requireSignin = passport.authenticate('local', { session: false} );

module.exports = function (app) {
  app.get('/', requireAuth, function(req, res) {
    res.send({ message: 'Super secret code is ABC123' });
  })
  app.post('/signin', requireSignin, Authentication.signin);
  app.post('/signup', Authentication.signup);
}
