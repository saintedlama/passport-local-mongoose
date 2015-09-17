var mongoose = require('mongoose');
var Schema = mongoose.Schema;
var assert = require('assert');
var passportLocalMongoose = require('../lib/passport-local-mongoose');
var mongotest = require('./helpers/mongotest');

describe('issues', function() {
  beforeEach(mongotest.prepareDb('mongodb://localhost/passportlocalmongooseissues'));
  afterEach(mongotest.disconnect());

  it('should support nested fields - Issue #9', function(done) {
    this.timeout(5000); // Five seconds - mongo db access needed

    var UserSchema = new Schema({
      sensitiveData1: String,
      sensitiveDate2: Number,
      account: {
        name: String,
        age: Number
      }
    });

    UserSchema.plugin(passportLocalMongoose, {usernameField: 'account.email'});
    var User = mongoose.model('ShouldSupportNestedFields_Issue_9', UserSchema);

    User.register({account: {email: 'nestedemail'}}, 'password', function(err, user) {
      assert.ifError(err);
      assert.ok(user);

      User.findByUsername('nestedemail', function(err, user) {
        assert.ifError(err);
        assert.ok(user);
        done();
      });
    });
  });

  it('should support not throw exception in case hash or salt are not stored - Issue #27', function(done) {
    this.timeout(5000); // Five seconds - mongo db access needed

    var UserSchema = new Schema({
      name: String,
      age: Number
    });

    UserSchema.plugin(passportLocalMongoose);
    var User = mongoose.model('ShouldNotThrowIfPasswordOrSaltAreNotStored_Issue_27', UserSchema);

    User.create({username: 'hugo', name: 'Hugo Wiener', age: 143}, function(err, user) {
      assert.ifError(err);
      assert.ok(user);

      User.authenticate()('hugo', 'none', function(err, auth, reason) {
        assert.ifError(err);
        assert.equal(false, auth);
        assert.ok(reason);

        assert.equal('Authentication not possible. No salt value stored in MongoDB collection', reason.message);

        done();
      });
    });
  });

  it('should support not throw exception in case hash and salt are not selected - Issue #27', function(done) {
    this.timeout(5000); // Five seconds - mongo db access needed

    var UserSchema = new Schema({
      name: String,
      age: Number
    });

    UserSchema.plugin(passportLocalMongoose, {selectFields: 'name'});
    var User = mongoose.model('ShouldNotThrowIfPasswordAndSaltAreNotSelected_Issue_27', UserSchema);

    User.register(new User({username: 'hugo'}), 'password', function(err, user) {
      assert.ifError(err);
      assert.ok(user);

      var authenticate = User.authenticate();

      authenticate('hugo', 'password', function(err, result) {
        assert.ifError(err);
        assert.ok(result instanceof User);

        done();
      });
    });
  });

  it('should populate fields in findByUsername if option is given - Issue #20', function(done) {
    this.timeout(5000); // Five seconds - mongo db access needed

    var LoginSchema = new Schema({date: Date, success: Boolean});
    var UserSchema = new Schema({logins: [{type: Schema.Types.ObjectId, ref: 'Login'}]});

    UserSchema.plugin(passportLocalMongoose, {populateFields: 'logins'});
    var User = mongoose.model('ShouldPopulateFields_Issue_20', UserSchema);
    var Login = mongoose.model('Login', LoginSchema);

    var loginDate = new Date();
    var loginSuccess = true;

    Login.create({date: loginDate, success: loginSuccess}, function(err, login) {
      assert.ifError(err);
      assert.ok(login);

      var logins = [];
      logins.push(login._id);

      User.register(new User({username: 'hugo', logins: logins}), 'password', function(err, user) {
        assert.ifError(err);
        assert.ok(user);

        User.findByUsername('hugo', function(err, loadedUser) {
          assert.ifError(err);
          assert.ok(loadedUser);
          assert.equal(loadedUser.logins.length, 1);

          assert.equal(loadedUser.logins[0].date.getTime(), loginDate.getTime());
          assert.equal(loadedUser.logins[0].success, loginSuccess);

          done();
        });
      });
    });
  });

  /* Since password is not directly stored with mongo/mongoose, password cannot be easily validated */
  it('should support password validation - Issue #57', function(done) {
    this.timeout(5000); // Five seconds - mongo db access needed

    var UserSchema = new Schema({});

    var nastyPasswordValidator = function(password, cb) {
      cb("My nasty error");
    };

    UserSchema.plugin(passportLocalMongoose, {
      passwordValidator: nastyPasswordValidator
    });
    var User = mongoose.model('ShouldSupportPasswordValidation_Issue_57', UserSchema);

    User.register({username: "nicolascage"}, 'password', function(err, user) {
      assert.equal(err, "My nasty error");
      done();
    });
  });

  it('should not expose hash and salt fields - Issue #72', function(done) {
    this.timeout(5000); // Five seconds - mongo db access needed

    var UserSchema = new Schema({});

    UserSchema.plugin(passportLocalMongoose, {});
    var User = mongoose.model('ShouldNotExposeHashAndSaltFields_Issue_72', UserSchema);

    User.register({username: "nicolascage"}, 'password', function(err, user) {
      assert.ifError(err);
      assert.ok(user);
      User.findOne({username: "nicolascage"}, function(err, user) {
        assert.ifError(err);
        assert.ok(user);
        assert.equal(user.username, "nicolascage");
        assert.strictEqual(user.hash, undefined);
        assert.strictEqual(user.salt, undefined);
        done();
      });
    });
  });

  describe('authentication should work with salt/hash field marked as select: false - Issue #96', function() {
    this.timeout(5000); // Five seconds - mongo db access needed
    var UserSchema = new Schema({});
    UserSchema.plugin(passportLocalMongoose, {});
    var userName = 'user_' + Math.random();
    var User = mongoose.model('ShouldAuthenticateWithSaltAndHashNotExposed_Issue_96', UserSchema);
    beforeEach(function(done) {
      User.register({username: userName}, 'password', function(err, user) {
        assert.ifError(err);
        assert.ok(user);
        done();
      });
    });

    it('instance.authenticate( password, callback )', function(done) {
      User.findOne({username: userName}, function(err, user) {
        assert.ifError(err);
        assert.ok(user);
        assert.equal(user.username, userName);
        user.authenticate('password', function(err, auth, reason) {
          assert.ifError(err);

          assert.ok(auth);
          done();
        });
      });
    });

    it('Model.autheticate(username, password, callback)', function(done) {
      User.authenticate()(userName, 'password', function(err, auth, reason) {
        assert.ifError(err);
        assert.ok(auth);

        done();
      });
    });
  });
});
