var mongoose = require('mongoose');
var Schema = mongoose.Schema;
var assert = require('assert');
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

        assert.equal('Authentication not possible. No salt value stored', reason.message);

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
  
  it('should not fail on parallel requests with reused query - Issue #124', function(done) {
    var UserSchema = new Schema({});
    UserSchema.plugin(passportLocalMongoose);

    var User = mongoose.model('ShouldNotFailOnParallelRequestsWithReusedQuery', UserSchema);
    
    var query = User.find({});
    var result = [];
    
    query.exec(function(err, users) {
        assert.ifError(err);
        
        result.push(users);
        if (result.length == 2) done();
    });
    
    query.count().exec(function(err, count) {
        assert.ifError(err);
        
        result.push(count);
        if (result.length == 2) done();
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

  describe('backward compatible #authenticate()', function() {
    it('should authenticate a user created in a 3.x version - issue #115', function(done) {
      var UserSchema = new Schema();
      UserSchema.plugin(passportLocalMongoose, {usernameLowerCase: true});
      var User = mongoose.model('AuthenticateBackwardCompatible', UserSchema);

      // 3.0 generated hash and salt of 'username', 'password'
      User.create({
        "salt" : "fd4bb06e65cd4d582efde28427ffdeb8839c64169d72cfe131bd971f70dc08f8",
        "hash" : "a52bb794337735fc69ce6c3af132e2854a10461a060e4ce07e3454a9ac65a4ad3e792ff1e17ebf3b20298fd11c737fd89a4bcb142d24f10673e0304833a858c94c798f967671b5923f43435941f9f54cc62a884d228c200f5ccfe52c680e2633d1335aaede1ec44e357dcacf832529974332aeac31f9fd10a0fded655f9117d9a6bea6c453e9499975ad7f7322b584910b843ef6af3324858bf635b26a3edc050e2e871c06bfc0a47d59449c9b6ffc6496c10b5cf3e688cfa699228a77f9457514a1203b98e5b8c37ee976d578ed3a9f0e530353ebb433ae06b1674282d173f52d5fd14e29498f4fa24c5b66223c4c0eb9cddf45c62590747d32109dbb94b8c57f9eaf671af6b15367b9cb184eff893f063d00ef3e1226337b30391a1411f6f6c50762a362ceec4411726856e298e179097c7ffc69f72c737424df901349cf6ce83da3d34bdc5117b2365634cf6069a0fb8363c1f5f2c8f994a7c1601980efd1135c76b88ac19d2a1547fe02c553dfb7d84b15438be90ecbb20bc69d0e6c11e370bf63a3b3efe03d84ef46d64cdca450c021593a4a483793f4ef2496125a1a5584a7f8b91df45db1723ab89b746cf100e655ca9cf64df4673eddbb13476ae7c9261f3389a14227f5103a31f1c2bce73c52e85cb6816dbb8fa9eb979b47ae003ad14cae156e6d832c743a0ad3ae9330a1c8528d3c896e3570019a959910ff9dd2",
        "username" : "username"
      }, function(err) {
        assert.ifError(err);

        User.authenticate()('username', 'password', function(err, authenticated) {
          assert.ifError(err);
          assert(authenticated);

          done();
        });
      });
    });
  });
});
