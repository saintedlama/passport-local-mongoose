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
    })
});