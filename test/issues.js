const mongoose = require('mongoose');
const Schema = mongoose.Schema;
const expect = require('chai').expect;
const dropMongodbCollections = require('drop-mongodb-collections');
const debug = require('debug')('passport:local:mongoose');
const passportLocalMongoose = require('../');

const dbName = 'passportlocalmongoosetests';
let connectionString = `mongodb://localhost:27017/${dbName}`;

if (process.env.MONGO_SERVER) {
  connectionString = connectionString.replace('mongodb://localhost', 'mongodb://' + process.env.MONGO_SERVER);
  debug('Using mongodb server from environment variable %s', connectionString);
}

describe('issues', function () {
  this.timeout(10000); // Ten seconds - mongodb access needed

  beforeEach(async () => await dropMongodbCollections(connectionString));
  beforeEach(() => mongoose.connect(connectionString, { bufferCommands: false, autoIndex: false }));
  afterEach(() => mongoose.disconnect());

  it('should support nested fields - Issue #9', async () => {
    const UserSchema = new Schema({
      sensitiveData1: String,
      sensitiveDate2: Number,
      account: {
        name: String,
        age: Number,
      },
    });

    UserSchema.plugin(passportLocalMongoose, { usernameField: 'account.email' });
    const User = mongoose.model('ShouldSupportNestedFields_Issue_9', UserSchema);

    const user = await User.register({ account: { email: 'nestedemail' } }, 'password');
    expect(user).to.exist;

    const foundUser = await User.findByUsername('nestedemail');
    expect(foundUser).to.exist;
  });

  it('should support not throw exception in case hash or salt are not stored - Issue #27', async () => {
    const UserSchema = new Schema({
      name: String,
      age: Number,
    });

    UserSchema.plugin(passportLocalMongoose);
    const User = mongoose.model('ShouldNotThrowIfPasswordOrSaltAreNotStored_Issue_27', UserSchema);

    const user = await User.create({ username: 'hugo', name: 'Hugo Wiener', age: 143 });
    expect(user).to.exist;

    const { user: auth, error } = await User.authenticate()('hugo', 'none');
    expect(false).to.equal(auth);
    expect(error).to.exist;
    expect('Authentication not possible. No salt value stored').to.equal(error.message);
  });

  it('should support not throw exception in case hash and salt are not selected - Issue #27', async () => {
    const UserSchema = new Schema({
      name: String,
      age: Number,
    });

    UserSchema.plugin(passportLocalMongoose, { selectFields: 'name' });
    const User = mongoose.model('ShouldNotThrowIfPasswordAndSaltAreNotSelected_Issue_27', UserSchema);

    const user = await User.register(new User({ username: 'hugo' }), 'password');
    expect(user).to.exist;

    const authenticate = User.authenticate();
    const { user: result } = await authenticate('hugo', 'password');
    expect(result).to.be.an.instanceOf(User);
  });

  it('should populate fields in findByUsername if option is given - Issue #20', async () => {
    const LoginSchema = new Schema({ date: Date, success: Boolean });
    const UserSchema = new Schema({ logins: [{ type: Schema.Types.ObjectId, ref: 'Login' }] });

    UserSchema.plugin(passportLocalMongoose, { populateFields: 'logins' });
    const User = mongoose.model('ShouldPopulateFields_Issue_20', UserSchema);
    const Login = mongoose.model('Login', LoginSchema);

    const loginDate = new Date();
    const loginSuccess = true;

    const login = await Login.create({ date: loginDate, success: loginSuccess });
    expect(login).to.exist;

    const logins = [];
    logins.push(login._id);

    const user = await User.register(new User({ username: 'hugo', logins: logins }), 'password');
    expect(user).to.exist;

    const loadedUser = await User.findByUsername('hugo');
    expect(loadedUser).to.exist;
    expect(loadedUser.logins.length).to.equal(1);

    expect(loadedUser.logins[0].date.getTime()).to.equal(loginDate.getTime());
    expect(loadedUser.logins[0].success).to.equal(loginSuccess);
  });

  /* Since password is not directly stored with mongo/mongoose, password cannot be easily validated */
  it('should support password validation - Issue #57', async () => {
    const UserSchema = new Schema({});

    async function passwordValidator(_password) {
      throw new Error('No password is valid');
    }

    UserSchema.plugin(passportLocalMongoose, {
      passwordValidator,
    });

    const User = mongoose.model('ShouldSupportPasswordValidation_Issue_57', UserSchema);

    try {
      await User.register({ username: 'nicolascage' }, 'password');
      throw new Error('Expected validation to fail');
    } catch (err) {
      expect(err.message).to.equal('No password is valid');
    }
  });

  it('should support password validation with promises - Issue #57', async () => {
    const UserSchema = new Schema({});

    function passwordValidator() {
      return Promise.reject(new Error('No password is valid'));
    }

    UserSchema.plugin(passportLocalMongoose, {
      passwordValidator,
    });

    const User = mongoose.model('ShouldSupportPasswordValidation_With_Promises_Issue_57', UserSchema);

    try {
      await User.register({ username: 'nicolascage' }, 'password');
      throw new Error('Expected password validator to throw!');
    } catch (err) {
      expect(err.message).to.equal('No password is valid');
    }
  });

  it('should not expose hash and salt fields - Issue #72', async () => {
    const UserSchema = new Schema({});

    UserSchema.plugin(passportLocalMongoose, {});
    const User = mongoose.model('ShouldNotExposeHashAndSaltFields_Issue_72', UserSchema);

    const user = await User.register({ username: 'nicolascage' }, 'password');
    expect(user).to.exist;

    const foundUser = await User.findOne({ username: 'nicolascage' });
    expect(foundUser).to.exist;
    expect(foundUser.username).to.equal('nicolascage');
    expect(foundUser.hash).to.equal(undefined);
    expect(foundUser.salt).to.equal(undefined);
  });

  describe('authentication should work with salt/hash field marked as select: false - Issue #96', function () {
    const UserSchema = new Schema({});
    UserSchema.plugin(passportLocalMongoose, {});
    const userName = 'user_' + Math.random();
    const User = mongoose.model('ShouldAuthenticateWithSaltAndHashNotExposed_Issue_96', UserSchema);

    beforeEach(async () => {
      const user = await User.register({ username: userName }, 'password');
      expect(user).to.exist;
    });

    it('instance.authenticate( password)', async function () {
      const user = await User.findOne({ username: userName });
      expect(user).to.exist;
      expect(user.username).to.equal(userName);

      const auth = await user.authenticate('password');
      expect(auth).to.exist;
    });

    it('Model.autheticate(username, password)', async function () {
      const auth = await User.authenticate()(userName, 'password');
      expect(auth).to.exist;
    });
  });

  describe('backward compatible #authenticate()', () => {
    it('should authenticate a user created in a 3.x version - issue #115', async () => {
      const UserSchema = new Schema();
      // Backward compatible digest is used: sha1 because pre node.js 0.12 this was the only supported digest algorithm!
      UserSchema.plugin(passportLocalMongoose, { usernameLowerCase: true, digestAlgorithm: 'sha1' });
      const User = mongoose.model('AuthenticateBackwardCompatible', UserSchema);

      // 3.0 generated hash and salt of 'username', 'password'
      await User.create({
        salt: 'fd4bb06e65cd4d582efde28427ffdeb8839c64169d72cfe131bd971f70dc08f8',
        hash: '2ce573e406497fcbc2c1e91532cdbcf198ecbe2692cd5b3dffc303c51e6ccf56ae6a1ed9bac17f6f185d2d289ed713f7bd2a7a6246a4974495a35ff95bba234e00757d8a78fb28836a984c3e67465a019ead84d684896712c50f670663134685225b6832ec5a0a99922eabe6ba03abc1e79bc6a29ca2fe23456034eff2987277331f9e32713b3293ab355882feebe9c37ecdcd1a22dcebd6e5799adeb6a4dc32e56398d21ece6eda07b84944c3918de6bda69ab7998be461f98ff1559a07fd5d3100d732da443110b3ac7d27d16098c4e1eab7489f6d2a5849981a5c9f5dadb86d8dbbb9b60ce67304e21221e77d1a2700cab460450702c16b99db2e3b67454765fe9e4054c87a9e436fb17db1774b9d22a129c1b120dad0925b58390b8a02241e7e06acbe87dbe7f0e91b5d000cd93fc7cc8f316f45b901b8eb58ea6853c8e7ead245a9329239ed4f3797bc12a151ffedd8e8d2533547a1aec7231a460ca128ebfb1bd6b6f988455505c21d2dbfe01ee4b321a3d20a5bf6e2a356b6f4dbb8ddb4cff7dc9779b9747881af4d08e2fbcf452746e07275ed350fad0d4e6e8fcbedb0575c1413be5a913ca6ef4fcf17d1021b93fe2b3b410cf612791f967521ae558459673156e431be5203ca944e80652559eaf3faa90250df3d24526d5f9fc3409e508a3e2175daaf492fd6efd748e4418834b631f84fe266ac32f4927c3a426b',
        username: 'username',
      });

      const authenticated = await User.authenticate()('username', 'password');
      expect(authenticated).to.exist;
    });
  });

  it('should support additional query restrictions in findByUsername - Issue #227', async () => {
    const UserSchema = new Schema({
      active: Boolean,
    });

    UserSchema.plugin(passportLocalMongoose, {
      // Needed to set usernameUnique to true to avoid a mongodb index on the username column!
      usernameUnique: false,

      findByUsername: function (model, queryParameters) {
        // Add additional query parameter - AND condition - active: true
        queryParameters.active = true;
        return model.findOne(queryParameters);
      },
    });

    const User = mongoose.model('ShouldSupportAdditionalQueryRestrictions', UserSchema);

    await User.register({ username: 'username', active: false }, 'password');

    const authenticate = User.authenticate();
    const { user: result } = await authenticate('username', 'password');

    // Expect that non active users must not authenticate successfully!
    expect(result).to.be.false;
  });

  it('should allow already registered but not active usernames to be taken again - Issue #227', async () => {
    const UserSchema = new Schema({
      active: Boolean,
    });

    UserSchema.plugin(passportLocalMongoose, {
      // Needed to set usernameUnique to true to avoid a mongodb index on the username column!
      usernameUnique: false,

      findByUsername: function (model, queryParameters) {
        // Add additional query parameter - AND condition - active: true
        queryParameters.active = true;
        return model.findOne(queryParameters);
      },
    });

    const User = mongoose.model('ShouldAllowRegisteredNonActiveUsernamesInRegister', UserSchema);

    await User.register({ username: 'username', active: false }, 'password');
    await User.register({ username: 'username', active: true }, 'password');

    const authenticate = User.authenticate();
    const { user } = await authenticate('username', 'password');

    // Expect that active users can authenticate!
    expect(user).to.exist;
  });
});
