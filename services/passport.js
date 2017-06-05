const User = require('../models/user');
const passport = require('passport');
const config = require('../config');
const JwtStrategy = require('passport-jwt').Strategy;
const ExtractJwt = require('passport-jwt').ExtractJwt;
const LocalStrategy = require('passport-local');

const localLogin = new LocalStrategy({ usernameField: 'email' }, function(email, password, done){
  User.findOne({ email: email }, function(err, user){
    if(err) { return done(err); }
    if(!user) { return done(null, false); }

    user.comparePassword(password, function(err, isMatch){
      if(err) { return done(err); }
      if(!isMatch) { return done(null, false); }
      done(null, user);
    });
  });
});

// jwt strategy configuration
const jwtOptions = {
  jwtFromRequest: ExtractJwt.fromHeader('authorization'),
  secretOrKey: config.secret,
}

//create jwt strategy
const jwtLogin = new JwtStrategy(jwtOptions, function(payload, done){
  User.findById(payload.sub, function(err, user){
    if(err) { return done(err, false); }
    if(user) {
      done(null, user);
    } else {
      done(null, false);
    }
  })
});

passport.use(jwtLogin);
passport.use(localLogin);