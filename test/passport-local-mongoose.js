var mongoose = require('mongoose'),
    Schema = mongoose.Schema,
    passportLocalMongoose = require('../lib/passport-local-mongoose'),
    assert = require('assert');

var modelUser = function(schemaValues, options) {
    var UserSchema = new Schema(schemaValues || {});
    UserSchema.plugin(passportLocalMongoose, options || {});

    return mongoose.model('User', UserSchema);
}

var setPasswordAndAuthenticate = function(user, passwordToSet, passwordToAuthenticate, cb) {
    user.setPassword(passwordToSet, function(err) {
        if (err) {
            return cb(err);
        }

        user.authenticate(passwordToAuthenticate, cb);
    });
}

describe('passportLocalMongoose', function() {
    describe('#plugin()', function() {
        it('should add "username" field to model', function() {
            var User = modelUser();
            var user = new User({ username : 'username' });

            assert.equal('username', user.username);
        });

        it('should add "salt" field to model', function() {
            var User = modelUser();
            var user = new User({ salt : 'salt' });

            assert.equal('salt', user.salt);
        });

        it('should add "hash" field to model', function() {
            var User = modelUser();
            var user = new User({ hash : 'hash' });

            assert.equal('hash', user.hash);
        });

        it('should add "setPassword" function to model', function() {
            var User = modelUser();
            var user = new User({});

            assert.equal('function', typeof(user.setPassword));
        });

        it('should add "authenticate" function to model', function() {
            var User = modelUser();

            var user = new User();
            assert.equal('function', typeof(user.authenticate));
        });

        it('should add static "authenticate" function', function() {
            var User = modelUser();

            assert.equal('function', typeof(User.authenticate));
        });
        
        it('should allow overriding "username" field name', function() {
            var UserSchema = new Schema({});
            UserSchema.plugin(passportLocalMongoose, { usernameField : 'email' });

            var User = mongoose.model('UsernameOverriddenUser', UserSchema);
            var user = new User();
            
            assert.ok(user.schema.path('email'));
        });

        it('should allow overriding "salt" field name', function() {
            var UserSchema = new Schema({});
            UserSchema.plugin(passportLocalMongoose, { saltField : 'passwordSalt' });

            var User = mongoose.model('SaltOverriddenUser', UserSchema);
            var user = new User();

            assert.ok(user.schema.path('passwordSalt'));
        });

        it('should allow overriding "hash" field name', function() {
            var UserSchema = new Schema({});
            UserSchema.plugin(passportLocalMongoose, { saltField : 'passwordHash' });

            var User = mongoose.model('HashOverriddenUser', UserSchema);
            var user = new User();

            assert.ok(user.schema.path('passwordHash'));
        });
    });

    describe('#setPassword()', function() {
        it('should set yield an error if password is undefined', function(done) {

            var User = modelUser();
            var user = new User();

            user.setPassword(undefined, function(err) {
                assert.ok(err);
                done();
            });
        });
        
        it('should set salt and hash', function(done) {
            this.timeout(5000); // Five seconds - heavy crypto in background

            var User = modelUser();
            var user = new User();

            user.setPassword('password', function(err, u) {
                assert.ifError(err);
                assert.ok(user.hash);
                assert.ok(user.salt);

                done();
            });
        });

        it('should authenticate user with arguments supplied to setPassword', function(done) {
            this.timeout(5000); // Five seconds - heavy crypto in background

            var User = modelUser();
            var user = new User();

            setPasswordAndAuthenticate(user, 'password', 'password', function(err, result) {
                assert.ifError(err);
                assert.equal(user, result);

                done();
            });
        });
    });

    describe('#authenticate()', function() {
       it('should yield false in case user cannot be authenticated', function(done) {
           this.timeout(5000); // Five seconds - heavy crypto in background

           var User = modelUser();
           var user = new User();

           setPasswordAndAuthenticate(user, 'password', 'nopassword', function(err, result) {
               assert.ifError(err);
               assert.ok(result === false);

               done();
           });
       });

        it('should supply a message when authentication fails', function(done) {
            this.timeout(5000); // Five seconds - heavy crypto in background

            var User = modelUser();
            var user = new User();

            setPasswordAndAuthenticate(user, 'password', 'nopassword', function(err, result, options) {
                assert.ifError(err);
                assert.ok(options.message);

                done();
            });
        });
    });

    describe('static #authenticate()', function() {
        var User = modelUser();
        
        before(function() {
            mongoose.connect('mongodb://localhost/passportlocalmongoosetests');
        });
        
        beforeEach(function(done){
            User.remove({}, done);
        });

        it('should yield false with message option for authenticate', function(done) {
            this.timeout(5000); // Five seconds - mongo db access needed

            User.authenticate()('user', 'password', function(err, result, options) {
                assert.ifError(err);
                assert.ok(result === false);
                assert.ok(options.message);

                done();
            });
        });

        it('should authenticate existing user with matching password', function(done) {
            this.timeout(5000); // Five seconds - mongo db access needed

            var user = new User({username : 'user'});
            user.setPassword('password', function(err) {
                assert.ifError(err);

                user.save(function(err) {
                    assert.ifError(err);

                    User.authenticate()('user', 'password', function(err, result) {
                        assert.ifError(err);
                        
                        assert.ok(result instanceof User);
                        assert.equal(user.username, result.username);
                        assert.equal(user.salt, result.salt);
                        assert.equal(user.hash, result.hash);

                        done();
                    });
                });
            });
        });

        it('should not authenticate existing user with non matching password', function(done) {
            this.timeout(5000); // Five seconds - mongo db access needed

            var user = new User({username : 'user'});
            user.setPassword('password', function(err) {
                assert.ifError(err);

                user.save(function(err) {
                    assert.ifError(err);

                    User.authenticate()('user', 'wrongpassword', function(err, result, options) {
                        assert.ifError(err);
                        assert.equal(result, false);
                        assert.ok(options.message);

                        done();
                    });
                });
            });
        });
    });

    describe('static #serializeUser()', function() {
       it('should define a static serializeUser function for passport', function() {
           var User = modelUser();
           assert.ok(User.serializeUser);
       });

        it('should serialize existing user by username field', function(done) {
            var User = modelUser();
            var user = new User({ username: 'user' });
            
            User.serializeUser()(user, function(err, username) {
                assert.equal('user', username);
                
                done();
            });
        });
    });

    describe('static #deserializeUser()', function() {
        it('should define a static deserializeUser function for passport', function() {
            var User = modelUser();
            assert.ok(User.deserializeUser);
        });

        it('should deserialize users by retrieving users from mongodb', function(done) {
            this.timeout(5000); // Five seconds - mongo db access needed
            
            var User = modelUser();
            var user = new User({username : 'user'});
            user.setPassword('password', function(err) {
                assert.ifError(err);
                
                user.save(function() {
                    User.deserializeUser()('user', function(err, loadedUser) {
                        assert.ifError(err);
                        assert.equal(user.username, loadedUser.username);

                        done();
                    });
                });
            });
        });

    });
});
