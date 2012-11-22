var crypto = require('crypto');

module.exports = function(schema, options) {
    options = options || {};
    options.saltlen = options.saltlen || 32;
    options.iterations = options.iterations || 25000;
    options.keylen = options.keylen || 512;

    schema.add({ username : String, hash: String, salt: String });

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

                var hash = new Buffer(hashRaw).toString('hex');

                self.hash = hash;
                self.salt = salt;

                cb(null, self);
            });
        });
    }

    schema.methods.authenticate = function(password, cb) {
        var self = this;

        // TODO: Fix callback and behavior to match passport
        crypto.pbkdf2(password, this.salt, options.iterations, options.keylen, function(err, hashRaw) {
            if (err) {
                return cb(err);
            }
            
            var hash = new Buffer(hashRaw).toString('hex');

            if (hash === self.hash) {
                return cb(null, self);
            } else {
                return cb(null, false, { message: 'Incorrect password' });
            }
        });
    }

    schema.statics.authenticate = function() {
        var self = this;

        return function(username, password, cb) {
            self.findOne({ username: username }, function(err, user) {
                if (err) { return cb(err); }
    
                if (user) {
                    return user.authenticate(password, cb);
                } else {
                    return cb(null, false, { message: 'Incorrect username' })
                }
            });
        }
    }

    schema.statics.serializeUser = function() {
        return function(user, cb) {
            cb(null, user.username);
        }
    }

    schema.statics.deserializeUser = function() {
        var self = this;
        
        return function(username, cb) {
            self.findOne({ username: username }, cb);
        }
    }
}
