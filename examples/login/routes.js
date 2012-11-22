var passport = require('passport'),
    Account = require('./models/account');

module.exports = function (app) {
    
    app.get('/', function (req, res) {
        res.render('index', { user : req.user });
    });

    app.get('/register', function(req, res) {
        res.render('register', { });
    });

    app.post('/register', function(req, res) {
        var username = req.body.username;
        
        Account.findOne({username : username }, function(err, existingUser) {
            if (err || existingUser) {
                return res.render('register', { account : account });
            }

            var account = new Account({ username : req.body.username });
            account.setPassword(req.body.password, function(err) {
                if (err) {
                    return res.render('register', { account : account });
                }

                account.save(function(err) {
                    if (err) {
                        return res.render('register', { account : account });
                    }

                    res.redirect('/');
                });
            });  
        });
    });

    app.get('/login', function(req, res) {
        res.render('login', { user : req.user });
    });

    app.post('/login', passport.authenticate('local'), function(req, res) {
        res.redirect('/');
    });

    app.get('/logout', function(req, res) {
        req.logout();
        res.redirect('/');
    });
}