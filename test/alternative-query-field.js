"use strict";
const mongoose = require('mongoose');
const Schema = mongoose.Schema;
const expect = require('chai').expect;
const passportLocalMongoose = require('../');
const mongotest = require('./helpers/mongotest');

describe('alternative query field', function() {
  this.timeout(10000); // Ten seconds - mongo db access needed

  beforeEach(mongotest.prepareDb('mongodb://localhost/passportlocalmongooseissues'));
  afterEach(mongotest.disconnect());

  it('should find an existing user by alternative query field', function(done) {
    const UserSchema = new Schema({
      email: String
    });
    UserSchema.plugin(passportLocalMongoose, {iterations: 1, usernameQueryFields: ['email']}); // 1 iteration - safes time in tests
    const User = mongoose.model('FindAlternativeQueryField', UserSchema);

    const email = 'hugo@test.org';
    const user = new User({username: 'hugo', email: email});
    user.save(function(err) {
      expect(err).to.not.exist;

      User.findByUsername(email, function(err, user) {
        expect(err).to.not.exist;
        expect(user).to.exist;
        expect(user.email).to.equal(email);

        done();
      });
    });
  });

  it('should authenticate an existing user by alternative query field', function(done) {
    const UserSchema = new Schema({
      email: String
    });
    UserSchema.plugin(passportLocalMongoose, {iterations: 1, usernameQueryFields: ['email']}); // 1 iteration - safes time in tests
    const User = mongoose.model('AuthenticateAlternativeQueryField', UserSchema);

    const email = 'hugo@test.org';
    const user = new User({username: 'hugo', email: email});
    User.register(user, 'password', function(err) {
      expect(err).to.not.exist;

      User.authenticate()('hugo@test.org', 'password', function(err, user, message) {
        expect(err).to.not.exist;
        expect(user).to.exist;
        expect(!message).to.exist;

        done();
      });
    });
  });

  it('should authenticate an existing user by default username field', function(done) {
    const UserSchema = new Schema({
      email: String
    });
    UserSchema.plugin(passportLocalMongoose, {iterations: 1, usernameQueryFields: ['email']}); // 1 iteration - safes time in tests
    const User = mongoose.model('AuthenticateDefaultField', UserSchema);

    const email = 'hugo@test.org';
    const user = new User({username: 'hugo', email: email});
    User.register(user, 'password', function(err) {
      expect(err).to.not.exist;

      User.authenticate()('hugo', 'password', function(err, user, message) {
        expect(err).to.not.exist;
        expect(user).to.exist;
        expect(!message).to.exist;

        done();
      });
    });
  });

  it('should not authenticate an existing user by unconfigured alternative query field', function(done) {
    const UserSchema = new Schema({
      email: String
    });
    UserSchema.plugin(passportLocalMongoose, {iterations: 1, usernameQueryFields: []}); // 1 iteration - safes time in tests
    const User = mongoose.model('NotAuthenticateUnconfiguredAlternativeQueryField', UserSchema);

    const email = 'hugo@test.org';
    const user = new User({username: 'hugo', email: email});
    User.register(user, 'password', function(err) {
      expect(err).to.not.exist;

      User.authenticate()('hugo@test.org', 'password', function(err, user, message) {
        expect(err).to.not.exist;
        expect(!user).to.exist;
        expect(message).to.exist;

        done();
      });
    });
  });
});
