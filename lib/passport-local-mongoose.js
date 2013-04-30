var crypto = require('crypto'),
    LocalStrategy = require('passport-local').Strategy;

module.exports = function(schema, options) {
    options = options || {};
    options.saltlen = options.saltlen || 32;
    options.iterations = options.iterations || 25000;
    options.keylen = options.keylen || 512;
    
    // Populate field names with defaults if not set
    options.usernameField = options.usernameField || 'username';
    options.hashField = options.hashField || 'hash';
    options.saltField = options.saltField || 'salt';

    var schemaFields = {};
    schemaFields[options.usernameField] = String;
    schemaFields[options.hashField] = String;
    schemaFields[options.saltField] = String;

    schema.add(schemaFields);

    schema.methods.setPassword = function (password, cb) {
        if (!password) {
            return cb(new Error("Password argument not set!"));
        }
        
        var self = this;

        crypto.randomBytes(options.saltlen, function(err, buf) {
            if (err) {
                return cb(err);
            }

            var salt = buf.toString('hex');

            crypto.pbkdf2(password, salt, options.iterations, options.keylen, function(err, hashRaw) {
                if (err) {
                    return cb(err);
                }

                self[options.hashField] = new Buffer(hashRaw, 'binary').toString('hex');
                self[options.saltField] = salt;

                cb(null, self);
            });
        });
    };

    schema.methods.authenticate = function(password, cb) {
        var self = this;

        // TODO: Fix callback and behavior to match passport
        crypto.pbkdf2(password, this[options.saltField], options.iterations, options.keylen, function(err, hashRaw) {
            if (err) {
                return cb(err);
            }
            
            var hash = new Buffer(hashRaw, 'binary').toString('hex');

            if (hash === self[options.hashField]) {
                return cb(null, self);
            } else {
                return cb(null, false, { message: 'Incorrect password' });
            }
        });
    };

    schema.statics.authenticate = function() {
        var self = this;

        return function(username, password, cb) {
            self.findByUsername(username, function(err, user) {
                if (err) { return cb(err); }

                if (user) {
                    return user.authenticate(password, cb);
                } else {
                    return cb(null, false, { message: 'Incorrect username' })
                }
            });
        }
    };

    schema.statics.serializeUser = function() {
        return function(user, cb) {
            cb(null, user[options.usernameField]);
        }
    };

    schema.statics.deserializeUser = function() {
        var self = this;

        return function(username, cb) {
            self.findByUsername(username, cb);
        }
    };
    
    schema.statics.register = function(user, password, cb) {
        if (!user[options.usernameField]) {
            return cb(new Error('Field ' + options.usernameField + ' is not set'));
        }

        // Create instances of this to ensure that user is an instance of user prototype
        user = new this(user);
        
        var self = this;
        self.findByUsername(user[options.usernameField], function(err, existingUser) {
            if (err) { return cb(err); }
            
            if (existingUser) {
                return cb(new Error('User already exists with name ' + user[options.usernameField]));
            }
            
            user.setPassword(password, function(err, user) {
                if (err) {
                    return cb(err);
                }

                user.save(function(err) {
                    if (err) {
                        return cb(err);
                    }

                    cb(null, user);
                });
            });
        });
    };

    schema.statics.findByUsername = function(username, cb) {
        var queryParameters = {};
        queryParameters[options.usernameField] = username;

        this.findOne(queryParameters, cb);
    };

    schema.statics.createStrategy = function() {
        return new LocalStrategy(options, this.authenticate());
    };
};
