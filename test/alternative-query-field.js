var mongoose = require('mongoose');
var Schema = mongoose.Schema;
var assert = require('assert');
var passportLocalMongoose = require('../lib/passport-local-mongoose');
var mongotest = require('./mongotest');

describe('alternative query field', function () {
    beforeEach(mongotest.prepareDb('mongodb://localhost/passportlocalmongooseissues'));
    afterEach(mongotest.disconnect());

    it('should find an existing user by alternative query field', function (done) {
        this.timeout(5000); // Five seconds - mongo db access needed

        var UserSchema = new Schema({
            email : String
        });
        UserSchema.plugin(passportLocalMongoose, { iterations : 1, usernameQueryFields : ['email'] }); // 1 iteration - safes time in tests
        var User = mongoose.model('FindAlternativeQueryField', UserSchema);

        var email = 'hugo@test.org';
        var user = new User({ username : 'hugo', email : email });
        user.save(function (err) {
            assert.ifError(err);

            User.findByUsername(email, function (err, user) {
                assert.ifError(err);
                assert.ok(user);
                assert.equal(user.email, email);

                done();
            });
        });
    });

    it('should authenticate an existing user by alternative query field', function (done) {
        this.timeout(5000); // Five seconds - mongo db access needed

        var UserSchema = new Schema({
            email : String
        });
        UserSchema.plugin(passportLocalMongoose, { iterations : 1, usernameQueryFields : ['email'] }); // 1 iteration - safes time in tests
        var User = mongoose.model('AuthenticateAlternativeQueryField', UserSchema);

        var email = 'hugo@test.org';
        var user = new User({ username : 'hugo', email : email });
        User.register(user, 'password', function (err) {
            assert.ifError(err);

            User.authenticate()('hugo@test.org', 'password', function(err, user, message) {
                assert.ifError(err);
                assert.ok(user);
                assert.ok(!message);

                done();
            });
        });
    });

    it('should authenticate an existing user by default username field', function (done) {
        this.timeout(5000); // Five seconds - mongo db access needed

        var UserSchema = new Schema({
            email : String
        });
        UserSchema.plugin(passportLocalMongoose, { iterations : 1, usernameQueryFields : ['email'] }); // 1 iteration - safes time in tests
        var User = mongoose.model('AuthenticateDefaultField', UserSchema);

        var email = 'hugo@test.org';
        var user = new User({ username : 'hugo', email : email });
        User.register(user, 'password', function (err) {
            assert.ifError(err);

            User.authenticate()('hugo', 'password', function(err, user, message) {
                assert.ifError(err);
                assert.ok(user);
                assert.ok(!message);

                done();
            });
        });
    });

    it('should not authenticate an existing user by unconfigured alternative query field', function (done) {
        this.timeout(5000); // Five seconds - mongo db access needed

        var UserSchema = new Schema({
            email : String
        });
        UserSchema.plugin(passportLocalMongoose, { iterations : 1, usernameQueryFields : [] }); // 1 iteration - safes time in tests
        var User = mongoose.model('NotAuthenticateUnconfiguredAlternativeQueryField', UserSchema);

        var email = 'hugo@test.org';
        var user = new User({ username : 'hugo', email : email });
        User.register(user, 'password', function (err) {
            assert.ifError(err);

            User.authenticate()('hugo@test.org', 'password', function(err, user, message) {
                assert.ifError(err);
                assert.ok(!user);
                assert.ok(message);

                done();
            });
        });
    });
});
