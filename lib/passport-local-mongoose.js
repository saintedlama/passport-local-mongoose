var crypto = require('crypto');

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

                self[options.hashField] = new Buffer(hashRaw).toString('hex');
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
            
            var hash = new Buffer(hashRaw).toString('hex');

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
            var queryParameters = {};
            queryParameters[options.usernameField] = username;
            
            self.findOne(queryParameters, function(err, user) {
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
            var queryParameters = {};
            queryParameters[options.usernameField] = username;

            self.findOne(queryParameters, cb);
        }
    };
};
