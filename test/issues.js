var mongoose = require('mongoose');
var Schema = mongoose.Schema;
var expect = require('chai').expect;
var passportLocalMongoose = require('../');
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
      expect(err).to.not.exist;
      expect(user).to.exist;

      User.findByUsername('nestedemail', function(err, user) {
        expect(err).to.not.exist;
        expect(user).to.exist;
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
      expect(err).to.not.exist;
      expect(user).to.exist;

      User.authenticate()('hugo', 'none', function(err, auth, reason) {
        expect(err).to.not.exist;
        expect(false).to.equal(auth);
        expect(reason).to.exist;

        expect('Authentication not possible. No salt value stored').to.equal(reason.message);

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
      expect(err).to.not.exist;
      expect(user).to.exist;

      var authenticate = User.authenticate();

      authenticate('hugo', 'password', function(err, result) {
        expect(err).to.not.exist;
        expect(result).to.be.an.instanceOf(User);

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
      expect(err).to.not.exist;
      expect(login).to.exist;

      var logins = [];
      logins.push(login._id);

      User.register(new User({username: 'hugo', logins: logins}), 'password', function(err, user) {
        expect(err).to.not.exist;
        expect(user).to.exist;

        User.findByUsername('hugo', function(err, loadedUser) {
          expect(err).to.not.exist;
          expect(loadedUser).to.exist;
          expect(loadedUser.logins.length).to.equal(1);

          expect(loadedUser.logins[0].date.getTime()).to.equal(loginDate.getTime());
          expect(loadedUser.logins[0].success).to.equal(loginSuccess);

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
      expect(err).to.equal("My nasty error");
      done();
    });
  });

  it('should not expose hash and salt fields - Issue #72', function(done) {
    this.timeout(5000); // Five seconds - mongo db access needed

    var UserSchema = new Schema({});

    UserSchema.plugin(passportLocalMongoose, {});
    var User = mongoose.model('ShouldNotExposeHashAndSaltFields_Issue_72', UserSchema);

    User.register({username: "nicolascage"}, 'password', function(err, user) {
      expect(err).to.not.exist;
      expect(user).to.exist;
      User.findOne({username: "nicolascage"}, function(err, user) {
        expect(err).to.not.exist;
        expect(user).to.exist;
        expect(user.username).to.equal("nicolascage");
        expect(user.hash).to.equal(undefined);
        expect(user.salt).to.equal(undefined);
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
        expect(err).to.not.exist;
        expect(user).to.exist;
        done();
      });
    });

    it('instance.authenticate( password, callback )', function(done) {
      User.findOne({username: userName}, function(err, user) {
        expect(err).to.not.exist;
        expect(user).to.exist;
        expect(user.username).to.equal(userName);
        user.authenticate('password', function(err, auth) {
          expect(err).to.not.exist;

          expect(auth).to.exist;
          done();
        });
      });
    });

    it('Model.autheticate(username, password, callback)', function(done) {
      User.authenticate()(userName, 'password', function(err, auth) {
        expect(err).to.not.exist;
        expect(auth).to.exist;

        done();
      });
    });
  });

  describe('backward compatible #authenticate()', function() {
    it('should authenticate a user created in a 3.x version - issue #115', function(done) {
      var UserSchema = new Schema();
      // Backward compatible digest is used: sha1 because pre node.js 0.12 this was the only supported digest algorithm!
      UserSchema.plugin(passportLocalMongoose, {usernameLowerCase: true, digestAlgorithm: 'sha1' });
      var User = mongoose.model('AuthenticateBackwardCompatible', UserSchema);

      // 3.0 generated hash and salt of 'username', 'password'
      User.create({
        "salt" : "fd4bb06e65cd4d582efde28427ffdeb8839c64169d72cfe131bd971f70dc08f8",
        "hash" : "2ce573e406497fcbc2c1e91532cdbcf198ecbe2692cd5b3dffc303c51e6ccf56ae6a1ed9bac17f6f185d2d289ed713f7bd2a7a6246a4974495a35ff95bba234e00757d8a78fb28836a984c3e67465a019ead84d684896712c50f670663134685225b6832ec5a0a99922eabe6ba03abc1e79bc6a29ca2fe23456034eff2987277331f9e32713b3293ab355882feebe9c37ecdcd1a22dcebd6e5799adeb6a4dc32e56398d21ece6eda07b84944c3918de6bda69ab7998be461f98ff1559a07fd5d3100d732da443110b3ac7d27d16098c4e1eab7489f6d2a5849981a5c9f5dadb86d8dbbb9b60ce67304e21221e77d1a2700cab460450702c16b99db2e3b67454765fe9e4054c87a9e436fb17db1774b9d22a129c1b120dad0925b58390b8a02241e7e06acbe87dbe7f0e91b5d000cd93fc7cc8f316f45b901b8eb58ea6853c8e7ead245a9329239ed4f3797bc12a151ffedd8e8d2533547a1aec7231a460ca128ebfb1bd6b6f988455505c21d2dbfe01ee4b321a3d20a5bf6e2a356b6f4dbb8ddb4cff7dc9779b9747881af4d08e2fbcf452746e07275ed350fad0d4e6e8fcbedb0575c1413be5a913ca6ef4fcf17d1021b93fe2b3b410cf612791f967521ae558459673156e431be5203ca944e80652559eaf3faa90250df3d24526d5f9fc3409e508a3e2175daaf492fd6efd748e4418834b631f84fe266ac32f4927c3a426b",
        "username" : "username"
      }, function(err) {
        expect(err).to.not.exist;

        User.authenticate()('username', 'password', function(err, authenticated) {
          expect(err).to.not.exist;
          expect(authenticated).to.exist;

          done();
        });
      });
    });
  });
});
