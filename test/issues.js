var mongoose = require('mongoose'),
    Schema = mongoose.Schema,
    passportLocalMongoose = require('../lib/passport-local-mongoose'),
    assert = require('assert');

describe('issues', function () {
    beforeEach(function (done) {
        this.timeout(5000); // Five seconds - give mongoose some time
        mongoose.connect('mongodb://localhost/passportlocalmongooseissues', done);
    });

    afterEach(function(done) {
        mongoose.disconnect(done);
    });

    it('should support nested fields - Issue #9', function(done) {
        var UserSchema = new Schema({
        sensitiveData1: String,
        sensitiveDate2: Number,
        account: {
            name: String,
            age: Number
        }
        });

        UserSchema.plugin(passportLocalMongoose, { usernameField: 'account.email' });
        var User = mongoose.model('ShouldSupportNestedFields_Issue_9', UserSchema);

        User.remove({}, function(err) {
            assert.ifError(err);

            User.register({ account : { email : 'nestedemail' }}, 'password', function (err, user) {
                assert.ifError(err);
                assert.ok(user);

                User.findByUsername('nestedemail', function (err, user) {
                    assert.ifError(err);
                    assert.ok(user);
                    done();
                });
            });
        });
    });

    it('should support not throw exception in case hash or salt are not stored - Issue #27', function(done) {
        var UserSchema = new Schema({
            name: String,
            age: Number
        });

        UserSchema.plugin(passportLocalMongoose);
        var User = mongoose.model('ShouldNotThrowIfPasswordOrSaltAreNotStored_Issue_27', UserSchema);

        User.remove({}, function(err) {
            assert.ifError(err);

            User.create({ username: 'hugo', name : 'Hugo Wiener', age : 143 }, function(err, user) {
                assert.ifError(err);
                assert.ok(user);

                User.authenticate()('hugo', 'none', function(err, auth, reason) {
                    assert.ifError(err);
                    assert.equal(false, auth);
                    assert.ok(reason);

                    assert.equal('User cannot be logged in. No salt value stored in mongodb', reason.message);

                    done();
                });
            });
        });
    });

    it('should support not throw exception in case hash and salt are not selected - Issue #27', function(done) {
        var UserSchema = new Schema({
            name: String,
            age: Number
        });

        UserSchema.plugin(passportLocalMongoose, { selectFields : 'name' });
        var User = mongoose.model('ShouldNotThrowIfPasswordAndSaltAreNotSelected_Issue_27', UserSchema);

        User.remove({}, function(err) {
            assert.ifError(err);

            User.register(new User({ username : 'hugo' }), 'password', function(err, user) {
                assert.ifError(err);
                assert.ok(user);

                var authenticate = User.authenticate();

                authenticate('hugo', 'password', function(err, auth, reason) {
                    assert.ifError(err);
                    assert.equal(false, auth);
                    assert.ok(reason);

                    assert.equal('User cannot be logged in. No salt value stored in mongodb', reason.message);

                    done();
                });
            });
        });
    });
});