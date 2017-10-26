"use strict";
const mongoose = require('mongoose');
const Schema = mongoose.Schema;
const errors = require('../lib/errors.js');
const passportLocalMongoose = require('../');
const expect = require('chai').expect;
const mongotest = require('./helpers/mongotest.js');

const DefaultUserSchema = new Schema();
DefaultUserSchema.plugin(passportLocalMongoose);
const DefaultUser = mongoose.model('DefaultUser', DefaultUserSchema);

describe('passportLocalMongoose', function() {
  this.timeout(10000); // Ten seconds - mongo db access needed

  it('should expose errors', function() {
    expect(passportLocalMongoose.errors).to.exist;
  });

  describe('#plugin()', function() {
    it('should add "username" field to model', function() {
      const user = new DefaultUser({username: 'username'});

      expect(user.username).to.equal('username');
    });

    it('should add "salt" field to model', function() {
      const user = new DefaultUser({salt: 'salt'});

      expect(user.salt).to.equal('salt')
    });

    it('should add "hash" field to model', function() {
      const user = new DefaultUser({hash: 'hash'});

      expect(user.hash).to.equal('hash')
    });

    it('should add "setPassword" function to model', function() {
      const user = new DefaultUser({});

      expect(typeof(user.setPassword)).to.equal('function')
    });

    it('should add "authenticate" function to model', function() {
      const user = new DefaultUser();
      expect(typeof(user.authenticate)).to.equal('function')
    });

    it('should add static "authenticate" function', function() {
      expect(typeof(DefaultUser.authenticate)).to.equal('function')
    });

    it('should allow overriding "username" field name', function() {
      const UserSchema = new Schema({});
      UserSchema.plugin(passportLocalMongoose, {usernameField: 'email'});

      const User = mongoose.model('UsernameOverriddenUser', UserSchema);
      const user = new User();

      expect(user.schema.path('email')).to.exist;
    });

    it('should allow overriding "salt" field name', function() {
      const UserSchema = new Schema({});
      UserSchema.plugin(passportLocalMongoose, {saltField: 'passwordSalt'});

      const User = mongoose.model('SaltOverriddenUser', UserSchema);
      const user = new User();

      expect(user.schema.path('passwordSalt')).to.exist;
    });

    it('should allow overriding "hash" field name', function() {
      const UserSchema = new Schema({});
      UserSchema.plugin(passportLocalMongoose, {saltField: 'passwordHash'});

      const User = mongoose.model('HashOverriddenUser', UserSchema);
      const user = new User();

      expect(user.schema.path('passwordHash')).to.exist;
    });

    it('should allow overriding "limitAttempts" option', function() {
      const UserSchema = new Schema({});
      UserSchema.plugin(passportLocalMongoose, {limitAttempts: true});

      const User = mongoose.model('LimitOverriddenUser', UserSchema);
      const user = new User();

      expect(user.schema.path('attempts')).to.exist;
    });

    it('should allow overriding "attempts" field name', function() {
      const UserSchema = new Schema({});
      UserSchema.plugin(passportLocalMongoose, {limitAttempts: true, attemptsField: 'failures'});

      const User = mongoose.model('AttemptsOverriddenUser', UserSchema);
      const user = new User();

      expect(user.schema.path('failures')).to.exist;
    });

    it('should preserve "username" field if already defined in the schema', function() {
      const usernameField = {type: String, required: true, unique: false};

      const UserSchema = new Schema({username: usernameField});
      UserSchema.plugin(passportLocalMongoose);

      const usernameFieldOptions = UserSchema.path('username').options;

      expect(usernameFieldOptions.type).to.deep.equal(usernameField.type);
      expect(usernameFieldOptions.required).to.deep.equal(usernameField.required);
      expect(usernameFieldOptions.unique).to.deep.equal(usernameField.unique);
    });

    it('should add "username" field to as unique model per default', function() {
      const UserSchema = new Schema({});
      UserSchema.plugin(passportLocalMongoose);

      expect(UserSchema.path('username').options.unique).to.equal(true);
    });

    it('should add "username" field to as non unique if specified by option', function() {
      const UserSchema = new Schema({});
      UserSchema.plugin(passportLocalMongoose, {usernameUnique: false});

      expect(UserSchema.path('username').options.unique).to.equal(false);
    });
  });

  describe('#setPassword()', function() {
    it('should set yield an error if password is undefined', function(done) {
      const user = new DefaultUser();

      user.setPassword(undefined, function(err) {
        expect(err).to.exist;
        done();
      });
    });

    it('should set salt and hash', function(done) {
      const user = new DefaultUser();

      user.setPassword('password', function(err) {
        expect(err).to.not.exist;
        expect(user.hash).to.exist;
        expect(user.salt).to.exist;

        done();
      });
    });

    it('should authenticate user with arguments supplied to setPassword', function(done) {
      const user = new DefaultUser();

      setPasswordAndAuthenticate(user, 'password', 'password', function(err, result) {
        expect(err).to.not.exist;
        expect(result).to.equal(user);

        done();
      });
    });
  });

  describe('#changePassword()', function() {
    beforeEach(mongotest.prepareDb('mongodb://localhost/passportlocalmongoosetests'));
    afterEach(mongotest.disconnect());

    it('should change password', function(done) {
      const user = new DefaultUser();

      user.setPassword('password1', function(err) {
        if (err) { return done(err); }

        user.changePassword('password1', 'password2', function(err, user) {
          if (err) { return done(err); }

          expect(user).to.exist;

          user.authenticate('password2', function(err, result) {
            if (err) { return done(err); }

            expect(result).to.exist;

            done();
          });
        });
      });
    });

    it('should fail on wrong password', function(done) {
      const user = new DefaultUser();

      user.setPassword('password1', function(err) {
        if (err) { return done(err); }

        user.changePassword('password2', 'password2', function(err) {
          expect(err).to.exist;

          done();
        });
      });
    });

    it('should not fail when passwords are the same', function(done) {
      const user = new DefaultUser();

      user.setPassword('password1', function(err) {
        if (err) { return done(err); }

        user.changePassword('password1', 'password1', function(err, user) {
          if (err) { return done(err); }

          expect(user).to.exist;

          done();
        });
      });
    });

    it('should change password when user model doesnt include salt/hash fields', function(done) {
      const user = new DefaultUser();

      user.setPassword('password1', function(err) {
        if (err) { return done(err); }

        delete user.salt;
        delete user.hash;

        user.changePassword('password1', 'password2', function(err, user) {
          if (err) { return done(err); }

          expect(user).to.exist;

          done();
        });
      });
    });
  });

  describe('#authenticate()', function() {

    beforeEach(mongotest.prepareDb('mongodb://localhost/passportlocalmongoosetests'));
    afterEach(mongotest.disconnect());

    it('should yield false in case user cannot be authenticated', function(done) {
      const user = new DefaultUser();

      setPasswordAndAuthenticate(user, 'password', 'nopassword', function(err, result) {
        expect(err).to.not.exist;
        expect(result).to.equal(false);

        done();
      });
    });

    it('should supply a message when authentication fails', function(done) {
      const user = new DefaultUser();

      setPasswordAndAuthenticate(user, 'password', 'nopassword', function(err, result, options) {
        expect(err).to.not.exist;
        expect(options.message).to.exist;

        done();
      });
    });

    it('should supply message when limiting attempts and authenticating too soon', function(done) {
      const UserSchema = new Schema({});
      UserSchema.plugin(passportLocalMongoose, {
        limitAttempts: true,
        interval: 20000
      });
      const User = mongoose.model('LimitAttemptsTooSoonUser', UserSchema);

      const user = new User({
        username: 'mark',
        attempts: 1,
        last: Date.now()
      });
      user.setPassword('password', function(err) {
        expect(err).to.not.exist;

        user.save(function(err) {
          expect(err).to.not.exist;

          user.authenticate('password', function(err, user, message) {
            expect(err).to.not.exist;
            expect(user).to.be.false;
            expect(message).to.be.instanceof(errors.AttemptTooSoonError);
            done();
          });
        });
      });
    });

    it('should get an error updating when limiting attempts and authenticating too soon', function(done) {
      const UserSchema = new Schema({}, {saveErrorIfNotFound: true});
      UserSchema.plugin(passportLocalMongoose, {
        limitAttempts: true,
        interval: 20000
      });
      const User = mongoose.model('LimitAttemptsTooSoonUpdateWithError', UserSchema);

      const user = new User({
        username: 'jimmy',
        attempts: 1,
        last: Date.now()
      });
      user.setPassword('password', function(err) {
        expect(err).to.not.exist;

        user.save(function(err) {
          expect(err).to.not.exist;

          user._id = mongoose.Types.ObjectId();
          user.authenticate('password', function(err, user, message) {
            expect(err).to.exist;
            expect(user).to.not.exist;
            expect(message).to.not.exist;
            done();
          });
        });
      });
    });

    it('should get an error updating the user on password match when limiting attempts', function(done) {
      const UserSchema = new Schema({}, {saveErrorIfNotFound: true});
      UserSchema.plugin(passportLocalMongoose, {
        limitAttempts: true
      });
      const User = mongoose.model('LimitAttemptsUpdateWithError', UserSchema);

      const user = new User({
        username: 'jane'
      });
      user.setPassword('password', function(err) {
        expect(err).to.not.exist;

        user.save(function(err) {
          expect(err).to.not.exist;

          user._id = mongoose.Types.ObjectId();
          user.authenticate('password', function(err, user, message) {
            expect(err).to.exist;
            expect(user).to.not.exist;
            expect(message).to.not.exist;
            done();
          });
        });
      });
    });

    it('should update the user on password match while limiting attempts', function(done) {


      const UserSchema = new Schema({});
      UserSchema.plugin(passportLocalMongoose, {
        limitAttempts: true
      });
      const User = mongoose.model('LimitAttemptsUpdateWithoutError', UserSchema);

      const user = new User({
        username: 'walter'
      });
      user.setPassword('password', function(err) {
        expect(err).to.not.exist;

        user.save(function(err) {
          expect(err).to.not.exist;

          user.authenticate('password', function(err, result, message) {
            expect(err).to.not.exist;
            expect(result).to.exist;
            expect(result.username).to.equal(user.username);
            expect(message).to.not.exist;
            done();
          });
        });
      });
    });

    it('should fail to update the user on password mismatch while limiting attempts', function(done) {
      const UserSchema = new Schema({}, {saveErrorIfNotFound: true});
      UserSchema.plugin(passportLocalMongoose, {
        limitAttempts: true,
        interval: 20000
      });
      const User = mongoose.model('LimitAttemptsMismatchWithAnError', UserSchema);

      const user = new User({
        username: 'wendy'
      });
      user.setPassword('password', function(err) {
        expect(err).to.not.exist;

        user.save(function(err) {
          expect(err).to.not.exist;

          user.hash = 'deadbeef'; // force an error on scmp with different length hex.
          user._id = mongoose.Types.ObjectId(); // force the save to fail
          user.authenticate('password', function(err, user, message) {
            expect(err).to.exist;
            expect(user).to.not.exist;
            expect(message).to.not.exist;
            done();
          });
        });
      });
    });

  });

  describe('static #authenticate()', function() {
    beforeEach(mongotest.prepareDb('mongodb://localhost/passportlocalmongoosetests'));
    afterEach(mongotest.disconnect());

    it('should yield false with message option for authenticate', function(done) {
      DefaultUser.authenticate()('user', 'password', function(err, result, options) {
        expect(err).to.not.exist;
        expect(result).to.equal(false);
        expect(options.message).to.exist;

        done();
      });
    });

    it('should authenticate existing user with matching password', function(done) {
      const user = new DefaultUser({username: 'user'});
      user.setPassword('password', function(err) {
        expect(err).to.not.exist;

        user.save(function(err) {
          expect(err).to.not.exist;

          DefaultUser.authenticate()('user', 'password', function(err, result) {
            expect(err).to.not.exist;

            expect(result instanceof DefaultUser).to.exist;
            expect(result.username).to.equal(user.username);

            expect(result.salt).to.equal(user.salt);
            expect(result.hash).to.equal(user.hash);

            done();
          });
        });
      });
    });

    it('should authenticate existing user with case insensitive username with matching password', function(done) {
      const UserSchema = new Schema();
      UserSchema.plugin(passportLocalMongoose, {usernameLowerCase: true});
      const User = mongoose.model('AuthenticateWithCaseInsensitiveUsername', UserSchema);

      const username = 'userName';
      User.register({username: username}, 'password', function(err) {
        expect(err).to.not.exist;

        User.authenticate()('username', 'password', function(err, result) {
          expect(err).to.not.exist;

          expect(result instanceof User).to.exist;
          expect('username').to.equal(result.username);

          done();
        });
      });
    });

    it('should authenticate existing user with matching password with field overrides', function(done) {
      const UserSchema = new Schema();
      UserSchema.plugin(passportLocalMongoose, {
        usernameField: 'email',
        hashField: 'hashValue',
        saltField: 'saltValue'
      });
      const User = mongoose.model('AuthenticateWithFieldOverrides', UserSchema);

      const email = 'emailUsedAsUsername';
      User.register({email: email}, 'password', function(err, user) {
        expect(err).to.not.exist;

        User.authenticate()(email, 'password', function(err, result) {
          expect(err).to.not.exist;

          expect(result instanceof User).to.exist;
          expect(result.email).to.equal(user.email);
          expect(result.saltValue).to.equal(user.saltValue);
          expect(result.hashValue).to.equal(user.hashValue);

          done();
        });
      });
    });

    it('should not authenticate existing user with non matching password', function(done) {
      const user = new DefaultUser({username: 'user'});
      user.setPassword('password', function(err) {
        expect(err).to.not.exist;

        user.save(function(err) {
          expect(err).to.not.exist;

          DefaultUser.authenticate()('user', 'wrongpassword', function(err, result, options) {
            expect(err).to.not.exist;
            expect(result).to.equal(false);
            expect(options.message).to.exist;

            done();
          });
        });
      });
    });

    it('should lock authenticate after too many login attempts', function(done) {
      const UserSchema = new Schema({});
      UserSchema.plugin(passportLocalMongoose, {limitAttempts: true, interval: 20000}); // High initial value for test

      const User = mongoose.model('LockUserAfterLimitAttempts', UserSchema);

      const user = new User({username: 'user'});
      user.setPassword('password', function(err) {
        expect(err).to.not.exist;

        user.save(function(err) {
          expect(err).to.not.exist;

          User.authenticate()('user', 'WRONGpassword', function(err, result) {
            expect(err).to.not.exist;
            expect(result).to.be.false;

            User.authenticate()('user', 'WRONGpassword', function(err, result) {
              expect(err).to.not.exist;
              expect(result).to.be.false;

              User.authenticate()('user', 'WRONGpassword', function(err, result) {
                expect(err).to.not.exist;
                expect(result).to.be.false;

                // Last login attempt should lock the user!
                User.authenticate()('user', 'password', function(err, result) {
                  expect(err).to.not.exist;
                  expect(result).to.be.false;

                  done();
                });
              });
            });
          });
        });
      });
    });

    it('should completely lock account after too many failed attempts', function(done) {
      const UserSchema = new Schema({});
      UserSchema.plugin(passportLocalMongoose, {
        limitAttempts: true,
        maxInterval: 1, // Don't require more than a millisecond of waiting
        maxAttempts: 3
      });

      const User = mongoose.model('LockUserPermanentlyAfterLimitAttempts', UserSchema);

      function authenticateWithWrongPassword(times, next) {
        if (times == 0) {
          return next();
        }

        User.authenticate()('user', 'WRONGpassword', function(err, result, data) {
          expect(err).to.not.exist;
          expect(result).to.be.false;

          times--;

          // Use should be locked at last login attempt
          if (times == 0) {
            expect(data.message).to.contain('locked');
          } else {
            expect(data.message).to.not.contain('locked');
          }

          authenticateWithWrongPassword(times, next);
        });
      }

      const user = new User({username: 'user'});
      user.setPassword('password', function(err) {
        expect(err).to.not.exist;

        user.save(function(err) {
          expect(err).to.not.exist;

          authenticateWithWrongPassword(3, function() {
            // Login attempt before should have locked the user!
            User.authenticate()('user', 'password', function(err, result, data) {
              expect(err).to.not.exist;
              expect(result).to.be.false;
              expect(data.message).to.contain('locked');

              user.resetAttempts(function(err) {
                expect(err).to.not.exist;

                // User should be unlocked
                User.authenticate()('user', 'password', function(err, result) {
                  expect(err).to.not.exist;
                  expect(result).to.exist;

                  done();
                });
              });
            });
          });
        });
      });
    });
  });


  describe('static #serializeUser()', function() {
    it('should define a static serializeUser function for passport', function() {
      expect(DefaultUser.serializeUser).to.exist;
    });

    it('should serialize existing user by username field', function(done) {
      const user = new DefaultUser({username: 'user'});

      DefaultUser.serializeUser()(user, function(err, username) {
        expect(username).to.equal('user');

        done();
      });
    });

    it('should serialize existing user by username field override', function(done) {
      const UserSchema = new Schema();
      UserSchema.plugin(passportLocalMongoose, {usernameField: 'email'});
      const User = mongoose.model('SerializeUserWithOverride', UserSchema);

      const user = new User({email: 'emailUsedForUsername'});

      User.serializeUser()(user, function(err, username) {
        expect(username).to.equal('emailUsedForUsername');

        done();
      });
    });
  });

  describe('static #deserializeUser()', function() {
    beforeEach(mongotest.prepareDb('mongodb://localhost/passportlocalmongoosetests'));
    afterEach(mongotest.disconnect());

    it('should define a static deserializeUser function for passport', function() {
      expect(DefaultUser.deserializeUser).to.exist;
    });

    it('should deserialize users by retrieving users from mongodb', function(done) {
      DefaultUser.register({username: 'user'}, 'password', function(err, user) {
        expect(err).to.not.exist;

        DefaultUser.deserializeUser()('user', function(err, loadedUser) {
          expect(err).to.not.exist;
          expect(loadedUser.username).to.equal(user.username)

          done();
        });
      });
    });

    it('should deserialize users by retrieving users from mongodb with username override', function(done) {
      const UserSchema = new Schema();
      UserSchema.plugin(passportLocalMongoose, {usernameField: 'email'});
      const User = mongoose.model('DeserializeUserWithOverride', UserSchema);

      const email = 'emailUsedForUsername';
      User.register({email: email}, 'password', function(err) {
        expect(err).to.not.exist;

        User.deserializeUser()(email, function(err, loadedUser) {
          expect(err).to.not.exist;
          expect(loadedUser.email).to.equal(email);

          done();
        });
      });
    });
  });

  describe('static #findByUsername()', function() {
    beforeEach(mongotest.prepareDb('mongodb://localhost/passportlocalmongoosetests'));
    afterEach(mongotest.disconnect());

    it('should define static findByUsername helper function', function() {
      const UserSchema = new Schema({});
      UserSchema.plugin(passportLocalMongoose, {});
      const User = mongoose.model('FindByUsernameDefined', UserSchema);

      expect(User.findByUsername).to.exist;
    });

    it('should retrieve saved user with findByUsername helper function', function(done) {
      const UserSchema = new Schema({});
      UserSchema.plugin(passportLocalMongoose, {});
      const User = mongoose.model('FindByUsername', UserSchema);

      const user = new User({username: 'hugo'});
      user.save(function(err) {
        expect(err).to.not.exist;

        User.findByUsername('hugo', function(err, user) {
          expect(err).to.not.exist;
          expect(user).to.exist;
          expect('hugo').to.equal(user.username);

          done();
        });
      });
    });

    it('should return a query object when no callback is specified', function(done) {
      const UserSchema = new Schema({});
      UserSchema.plugin(passportLocalMongoose, {});
      const User = mongoose.model('FindByUsernameQueryObject', UserSchema);

      const user = new User({username: 'hugo'});
      user.save(function(err) {
        expect(err).to.not.exist;

        const query = User.findByUsername('hugo');

        expect(query).to.exist;

        query.exec(function(err, user) {
          expect(err).to.not.exist;
          expect(user).to.exist;
          expect(user.username).to.equal('hugo');

          done();
        });
      });
    });

    it('should select all fields', function(done) {
      const UserSchema = new Schema({department: {type: String, required: true}});
      UserSchema.plugin(passportLocalMongoose, {});
      const User = mongoose.model('FindByUsernameWithAllFields', UserSchema);

      const user = new User({username: 'hugo', department: 'DevOps'});
      user.save(function(err) {
        expect(err).to.not.exist;

        User.findByUsername('hugo', function(err, user) {
          expect(err).to.not.exist;
          expect(user).to.exist;
          expect(user.username).to.equal('hugo');
          expect(user.department).to.equal('DevOps');

          done();
        });
      });
    });

    it('should select fields specified by selectFields option', function(done) {
      const UserSchema = new Schema({department: {type: String, required: true}});
      UserSchema.plugin(passportLocalMongoose, {selectFields: 'username'});
      const User = mongoose.model('FindByUsernameWithSelectFieldsOption', UserSchema);

      const user = new User({username: 'hugo', department: 'DevOps'});
      user.save(function(err) {
        expect(err).to.not.exist;

        User.findByUsername('hugo', function(err, user) {
          expect(err).to.not.exist;
          expect(user).to.exist;
          expect(user.username).to.equal('hugo');
          expect(user.department).to.equal(undefined);

          done();
        });
      });
    });

    it('should retrieve saved user with findByUsername helper function with username field override', function(done) {
      const UserSchema = new Schema({});
      UserSchema.plugin(passportLocalMongoose, {usernameField: 'email'});
      const User = mongoose.model('FindByUsernameWithOverride', UserSchema);

      const email = 'emailUsedForUsername';
      const user = new User({email: email});

      user.save(function(err) {
        expect(err).to.not.exist;

        User.findByUsername(email, function(err, user) {
          expect(err).to.not.exist;
          expect(user).to.exist;
          expect(email).to.equal(user.email);

          done();
        });
      });
    });

    it('should not throw if lowercase option is specified and no username is supplied', function(done) {
      const UserSchema = new Schema({});
      UserSchema.plugin(passportLocalMongoose, {usernameLowerCase: true});
      const User = mongoose.model('FindByUsernameWithUndefinedUsername', UserSchema);

      User.findByUsername(undefined, function(err) {
        expect(err).to.not.exist;
        done();
      });
    });
  });

  describe('static #register()', function() {
    beforeEach(mongotest.prepareDb('mongodb://localhost/passportlocalmongoosetests'));
    afterEach(mongotest.disconnect());

    it('should define static register helper function', function() {
      const UserSchema = new Schema({});
      UserSchema.plugin(passportLocalMongoose, {});
      const User = mongoose.model('RegisterDefined', UserSchema);

      expect(User.register).to.exist;
    });

    it('should register user', function(done) {
      const UserSchema = new Schema({});
      UserSchema.plugin(passportLocalMongoose, {});
      const User = mongoose.model('RegisterUser', UserSchema);

      User.register({username: 'hugo'}, 'password', function(err, user) {
        expect(err).to.not.exist;
        expect(user).to.exist;

        User.findByUsername('hugo', function(err, user) {
          expect(err).to.not.exist;
          expect(user).to.exist;
          done();
        });
      });
    });

    it('should check for duplicate user name', function(done) {
      const UserSchema = new Schema({});
      UserSchema.plugin(passportLocalMongoose, {});
      const User = mongoose.model('RegisterDuplicateUser', UserSchema);

      User.register({username: 'hugo'}, 'password', function(err) {
        expect(err).to.not.exist;

        User.register({username: 'hugo'}, 'password', function(err) {
          expect(err).to.exist;
          done();
        });
      });
    });

    it('should authenticate registered user', function(done) {
      const UserSchema = new Schema({});
      UserSchema.plugin(passportLocalMongoose, {iterations: 1}); // 1 iteration - safes time in tests
      const User = mongoose.model('RegisterAndAuthenticateUser', UserSchema);

      User.register({username: 'hugo'}, 'password', function(err) {
        expect(err).to.not.exist;

        User.authenticate()('hugo', 'password', function(err, user, message) {
          expect(err).to.not.exist;
          expect(user).to.exist;
          expect(message).to.not.exist;

          done();
        });
      });
    });

    it('should not authenticate registered user with wrong password', function(done) {
      const UserSchema = new Schema({});
      UserSchema.plugin(passportLocalMongoose, {iterations: 1}); // 1 iteration - safes time in tests
      const User = mongoose.model('RegisterAndNotAuthenticateUser', UserSchema);

      User.register({username: 'hugo'}, 'password', function(err) {
        expect(err).to.not.exist;

        User.authenticate()('hugo', 'wrong_password', function(err, user, message) {
          expect(err).to.not.exist;
          expect(user).to.equal(false);
          expect(message).to.exist;

          done();
        });
      });
    });

    it('it should add username existing user without username', function(done) {
      const UserSchema = new Schema({});
      UserSchema.plugin(passportLocalMongoose, {});
      const User = mongoose.model('RegisterExistingUser', UserSchema);

      const existingUser = new User({});
      existingUser.save(function(err, user) {
        expect(err).to.not.exist;
        expect(user).to.exist;

        user.username = 'hugo';
        User.register(user, 'password', function(err, user) {
          expect(err).to.not.exist;
          expect(user).to.exist;

          User.findByUsername('hugo', function(err, user) {
            expect(err).to.not.exist;
            expect(user).to.exist;
            done();
          });
        });
      });
    });

    it('should result in AuthenticationError error in case no username was given', function(done) {
      const UserSchema = new Schema({});
      UserSchema.plugin(passportLocalMongoose, {});
      const User = mongoose.model('RegisterUserWithoutUsername', UserSchema);

      User.register({}, 'password', function(err) {
        expect(err).to.be.instanceof(errors.AuthenticationError);
        done();
      });
    });

    it('should result in AuthenticationError error in case no password was given', function(done) {
      const UserSchema = new Schema({});
      UserSchema.plugin(passportLocalMongoose, {});
      const User = mongoose.model('RegisterUserWithoutPassword', UserSchema);

      User.register({username: 'hugo'}, undefined, function(err) {
        expect(err).to.be.instanceof(errors.AuthenticationError);
        done();
      });
    });
  });

  describe('static #createStrategy()', function() {
    it('should create strategy', function() {
      const UserSchema = new Schema({});
      UserSchema.plugin(passportLocalMongoose, {usernameField: 'email'});
      const User = mongoose.model('CreateStrategy', UserSchema);

      const strategy = User.createStrategy();
      expect(strategy).to.exist;
    });
  });
});

function setPasswordAndAuthenticate(user, passwordToSet, passwordToAuthenticate, cb) {
  user.setPassword(passwordToSet, function(err) {
    if (err) {
      return cb(err);
    }

    user.authenticate(passwordToAuthenticate, cb);
  });
}