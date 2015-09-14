var passport = require('passport');
var Account = require('./models/account');
var router = require('express').Router();

router.get('/', function(req, res) {
  res.render('index', {user: req.user});
});

router.get('/register', function(req, res) {
  res.render('register', {});
});

router.post('/register', function(req, res, next) {
  console.log('registering user');
  Account.register(new Account({username: req.body.username}), req.body.password, function(err) {
    if (err) {
      console.log('error while user register!', err);
      return next(err);
    }

    console.log('user registered!');

    res.redirect('/');
  });
});

router.get('/login', function(req, res) {
  res.render('login', {user: req.user});
});

router.post('/login', passport.authenticate('local'), function(req, res) {
  res.redirect('/');
});

router.get('/logout', function(req, res) {
  req.logout();
  res.redirect('/');
});

module.exports = router;