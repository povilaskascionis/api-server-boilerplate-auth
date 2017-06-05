const User = require('../models/user');
const jwt = require('jwt-simple');
const config = require('../config');

function createUserToken(user) {
  const timestamp = new Date().getTime();
  return jwt.encode({ sub: user.id, iat: timestamp }, config.secret)
}

exports.signin = function(req, res, next) {
  res.send({ token: createUserToken(req.user) });
}

exports.signup = function(req, res, next) {
  const email = req.body.email;
  const password = req.body.password;

  if (!email || !password) {
    return res.status(422).send({error: "email and password are mandatory"})
  }

  User.findOne({email: email}, function(err, existingUser){
    if(existingUser){
      return res.status(422).send({ error: "Email is already in use" });
    }

    const user = new User({
      email: email,
      password: password
    })

    user.save(function(err){
      if (err) { return next(err) }

      res.json({ token: createUserToken(user) });
    })
  });
}