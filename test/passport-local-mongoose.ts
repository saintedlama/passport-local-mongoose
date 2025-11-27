import mongoose, { Schema } from 'mongoose';
import dropMongodbCollections from 'drop-mongodb-collections';
import Debug from 'debug';
import { errors } from '../dist/index.js';
import passportLocalMongoose from '../dist/index.js';

const debug = Debug('passport:local:mongoose');

const DefaultUserSchema = new Schema();
DefaultUserSchema.plugin(passportLocalMongoose);
const DefaultUser = mongoose.model('DefaultUser', DefaultUserSchema);

const dbName = 'passportlocalmongoosetests';
let connectionString = `mongodb://localhost:27017/${dbName}`;

if (process.env.MONGO_SERVER) {
  connectionString = connectionString.replace('mongodb://localhost', 'mongodb://' + process.env.MONGO_SERVER);
  debug('Using mongodb server from environment variable %s', connectionString);
}

describe('passportLocalMongoose', function () {
  it('should expose errors', function () {
    expect(passportLocalMongoose.errors).to.exist;
  });

  describe('#plugin()', function () {
    it('should add "username" field to model', function () {
      const user = new DefaultUser({ username: 'username' });

      expect(user.username).to.equal('username');
    });

    it('should add "salt" field to model', function () {
      const user = new DefaultUser({ salt: 'salt' });

      expect(user.salt).to.equal('salt');
    });

    it('should add "hash" field to model', function () {
      const user = new DefaultUser({ hash: 'hash' });

      expect(user.hash).to.equal('hash');
    });

    it('should add "setPassword" function to model', function () {
      const user = new DefaultUser({});

      expect(typeof user.setPassword).to.equal('function');
    });

    it('should add "authenticate" function to model', function () {
      const user = new DefaultUser();
      expect(typeof user.authenticate).to.equal('function');
    });

    it('should add static "authenticate" function', function () {
      expect(typeof DefaultUser.authenticate).to.equal('function');
    });

    it('should allow overriding "username" field name', function () {
      const UserSchema = new Schema({});
      UserSchema.plugin(passportLocalMongoose, { usernameField: 'email' });

      const User = mongoose.model('UsernameOverriddenUser', UserSchema);
      const user = new User();

      expect(user.schema.path('email')).to.exist;
    });

    it('should allow overriding "salt" field name', function () {
      const UserSchema = new Schema({});
      UserSchema.plugin(passportLocalMongoose, { saltField: 'passwordSalt' });

      const User = mongoose.model('SaltOverriddenUser', UserSchema);
      const user = new User();

      expect(user.schema.path('passwordSalt')).to.exist;
    });

    it('should allow overriding "hash" field name', function () {
      const UserSchema = new Schema({});
      UserSchema.plugin(passportLocalMongoose, { saltField: 'passwordHash' });

      const User = mongoose.model('HashOverriddenUser', UserSchema);
      const user = new User();

      expect(user.schema.path('passwordHash')).to.exist;
    });

    it('should allow overriding "limitAttempts" option', function () {
      const UserSchema = new Schema({});
      UserSchema.plugin(passportLocalMongoose, { limitAttempts: true });

      const User = mongoose.model('LimitOverriddenUser', UserSchema);
      const user = new User();

      expect(user.schema.path('attempts')).to.exist;
    });

    it('should allow overriding "attempts" field name', function () {
      const UserSchema = new Schema({});
      UserSchema.plugin(passportLocalMongoose, { limitAttempts: true, attemptsField: 'failures' });

      const User = mongoose.model('AttemptsOverriddenUser', UserSchema);
      const user = new User();

      expect(user.schema.path('failures')).to.exist;
    });

    it('should preserve "username" field if already defined in the schema', function () {
      const usernameField = { type: String, required: true, unique: false };

      const UserSchema = new Schema({ username: usernameField });
      UserSchema.plugin(passportLocalMongoose);

      const usernameFieldOptions = UserSchema.path('username')!.options;

      expect(usernameFieldOptions.type).to.deep.equal(usernameField.type);
      expect(usernameFieldOptions.required).to.deep.equal(usernameField.required);
      expect(usernameFieldOptions.unique).to.deep.equal(usernameField.unique);
    });

    it('should add "username" field to as unique model per default', function () {
      const UserSchema = new Schema({});
      UserSchema.plugin(passportLocalMongoose);

      expect(UserSchema.path('username')!.options.unique).to.equal(true);
    });

    it('should add "username" field to as non unique if specified by option', function () {
      const UserSchema = new Schema({});
      UserSchema.plugin(passportLocalMongoose, { usernameUnique: false });

      expect(UserSchema.path('username')!.options.unique).to.equal(false);
    });
  });

  describe('#setPassword()', function () {
    it('should set yield an error if password is undefined', async () => {
      const user = new DefaultUser();

      try {
        await (user as any).setPassword();
        throw new Error('Should yieldd an error if password is undefined');
      } catch (_err) {
        // Expected error
        return;
      }
    });

    it('should set salt and hash', async () => {
      const user = new DefaultUser();

      const result = await user.setPassword('password');
      expect(result.hash).to.exist;
      expect(result.salt).to.exist;
    });

    it('should authenticate user with arguments supplied to setPassword', async () => {
      const user = new DefaultUser();

      const result = await setPasswordAndAuthenticate(user, 'password', 'password');
      expect(result.user).to.equal(user);
    });
  });

  describe('#changePassword()', function () {
    beforeEach(async () => await dropMongodbCollections(connectionString));
    beforeEach(() => mongoose.connect(connectionString, { bufferCommands: false, autoIndex: false }));
    afterEach(() => mongoose.disconnect());

    it('should change password', async () => {
      const user = new DefaultUser();

      await user.setPassword('password1');
      const changePasswordUser = await user.changePassword('password1', 'password2');
      const authenticatedUser = await changePasswordUser.authenticate('password2');

      expect(authenticatedUser).to.exist;
    });

    it('should fail on wrong password', async () => {
      const user = new DefaultUser();

      await user.setPassword('password1');

      try {
        await user.changePassword('password2', 'password2');
      } catch (_err) {
        return;
      }

      throw new Error('Expected "changePassword" to throw');
    });

    it('should not fail when passwords are the same', async () => {
      const user = new DefaultUser();

      await user.setPassword('password1');
      const changePasswordUser = await user.changePassword('password1', 'password1');

      expect(changePasswordUser).to.exist;
    });

    it('should change password when user model doesnt include salt/hash fields', async () => {
      const user = new DefaultUser();

      await user.setPassword('password1');

      delete (user as any).salt;
      delete (user as any).hash;

      const changePasswordUser = await user.changePassword('password1', 'password2');
      expect(changePasswordUser).to.exist;
    });

    it('should fail when no replacement password given', async () => {
      const user = new DefaultUser();

      await user.setPassword('password1');

      try {
        await user.changePassword('password1', '');
        throw new Error('Expected changePassword to throw');
      } catch (err) {
        expect(err).to.be.instanceof(errors.MissingPasswordError);
      }
    });
  });

  describe('#authenticate() async', function () {
    beforeEach(async () => await dropMongodbCollections(connectionString));
    beforeEach(() => mongoose.connect(connectionString, { bufferCommands: false, autoIndex: false }));
    afterEach(() => mongoose.disconnect());

    it('should yield false with error message in case user cannot be authenticated', async () => {
      const user = new DefaultUser();

      await user.setPassword('password');
      const { user: authenticatedUser, error } = await user.authenticate('nopassword');

      expect(authenticatedUser).to.be.false;
      expect(error!.message).to.equal('Password or username is incorrect');
    });

    it('should supply message when limiting attempts and authenticating too soon', async () => {
      const UserSchema = new Schema({});
      UserSchema.plugin(passportLocalMongoose, {
        limitAttempts: true,
        interval: 20000,
      });
      const User = mongoose.model('LimitAttemptsTooSoonUserAsync', UserSchema);

      const user = new User({
        username: 'mark',
        attempts: 1,
        last: Date.now(),
      });

      await user.setPassword('password');
      await user.save();

      const { user: authenticatedUser, error } = await user.authenticate('password');

      expect(authenticatedUser).to.be.false;
      expect(error).to.be.instanceof(errors.AttemptTooSoonError);
    });

    it('should get an error updating when limiting attempts and authenticating too soon', async () => {
      const UserSchema = new Schema({}, { saveErrorIfNotFound: true });
      UserSchema.plugin(passportLocalMongoose, {
        limitAttempts: true,
        interval: 20000,
      });
      const User = mongoose.model('LimitAttemptsTooSoonUpdateWithErrorAsync', UserSchema);

      const user = new User({
        username: 'jimmy',
        attempts: 1,
        last: Date.now(),
      });

      await user.setPassword('password');
      await user.save();

      const { user: authenticatedUser, error } = await user.authenticate('password');

      expect(authenticatedUser).to.be.false;
      expect(error).to.be.instanceof(errors.AttemptTooSoonError);
    });

    it('should update the user on password match while limiting attempts', async () => {
      const UserSchema = new Schema({});
      UserSchema.plugin(passportLocalMongoose, {
        limitAttempts: true,
      });
      const User = mongoose.model('LimitAttemptsUpdateWithoutErrorAsync', UserSchema);

      const user = new User({
        username: 'walter',
      });

      await user.setPassword('password');
      await user.save();

      const { user: authenticatedUser, error } = await user.authenticate('password');

      expect(authenticatedUser).to.exist;
      expect(authenticatedUser.username).to.equal(user.username);
      expect(error).to.not.exist;
    });

    it('should fail to update the user on password mismatch while limiting attempts', async () => {
      const UserSchema = new Schema({}, { saveErrorIfNotFound: true });
      UserSchema.plugin(passportLocalMongoose, {
        limitAttempts: true,
        interval: 20000,
      });
      const User = mongoose.model('LimitAttemptsMismatchWithAnErrorAsync', UserSchema);

      const user = new User({
        username: 'wendy',
      });
      await user.setPassword('password');
      await user.save();

      const { user: authenticatedUser, error } = await user.authenticate('WRONGpassword');

      expect(authenticatedUser).to.be.false;
      expect(error).to.be.instanceof(errors.IncorrectPasswordError);
    });

    it('should supply message if username is not registered', async () => {
      const user = new DefaultUser({
        username: 'andrew',
      });
      const { user: authenticatedUser, error } = await user.authenticate('password');

      expect(authenticatedUser).to.be.false;
      expect(error!.message).to.exist;
    });
  });

  describe('static #authenticate() async', function () {
    beforeEach(async () => await dropMongodbCollections(connectionString));
    beforeEach(() => mongoose.connect(connectionString, { bufferCommands: false, autoIndex: false }));
    afterEach(() => mongoose.disconnect());

    it('should yield false with message option for authenticate', async () => {
      const { user, error } = await DefaultUser.authenticate()('user', 'password');

      expect(user).to.equal(false);
      expect(error).to.exist;
    });

    it('should authenticate existing user with matching password', async () => {
      const user = new DefaultUser({ username: 'user' });
      await user.setPassword('password');
      await user.save();
      const { user: result } = await DefaultUser.authenticate()('user', 'password');

      expect(result).to.be.instanceof(DefaultUser);
      expect(result.username).to.equal(user.username);

      expect(result.salt).to.equal(user.salt);
      expect(result.hash).to.equal(user.hash);
    });

    it('should authenticate existing user with usernameLowerCase enabled and with matching password', async () => {
      const UserSchema = new Schema();
      UserSchema.plugin(passportLocalMongoose, { usernameLowerCase: true });
      const User = mongoose.model('AuthenticateWithLowerCaseUsernameAsync', UserSchema);

      const username = 'userName';
      await User.register({ username: username }, 'password');

      const { user: result } = await User.authenticate()('username', 'password');

      expect(result).to.be.instanceof(User);
      expect('username').to.equal(result.username);
    });

    it('should authenticate existing user with case insensitive username with matching password', async () => {
      const UserSchema = new Schema();
      UserSchema.plugin(passportLocalMongoose, { usernameCaseInsensitive: true });
      const User = mongoose.model('AuthenticateWithCaseInsensitiveUsernameAsync', UserSchema);

      const username = 'userName';
      await User.register({ username: username }, 'password');

      const { user: result } = await User.authenticate()('username', 'password');

      expect(result).to.be.instanceof(User);
      expect(username).to.equal(result.username);
    });

    it('should authenticate existing user with matching password with field overrides', async () => {
      const UserSchema = new Schema();
      UserSchema.plugin(passportLocalMongoose, {
        usernameField: 'email',
        hashField: 'hashValue',
        saltField: 'saltValue',
      });
      const User = mongoose.model('AuthenticateWithFieldOverridesAsync', UserSchema);

      const email = 'emailUsedAsUsername';
      const user = await User.register({ email: email }, 'password');

      const { user: result } = await User.authenticate()(email, 'password');

      expect(result).to.be.instanceof(User);
      expect(result.email).to.equal(user.email);
      expect(result.saltValue).to.equal(user.saltValue);
      expect(result.hashValue).to.equal(user.hashValue);
    });

    it('should not authenticate existing user with non matching password', async () => {
      const user = new DefaultUser({ username: 'user' });
      await user.setPassword('password');
      await user.save();

      const { user: result, error } = await DefaultUser.authenticate()('user', 'wrongpassword');

      expect(result).to.equal(false);
      expect(error).to.exist;
    });

    it('should lock authenticate after too many login attempts', async () => {
      const UserSchema = new Schema({});
      UserSchema.plugin(passportLocalMongoose, { limitAttempts: true, interval: 20000 }); // High initial value for test

      const User = mongoose.model('LockUserAfterLimitAttemptsAsync', UserSchema);

      const user = new User({ username: 'user' });
      await user.setPassword('password');

      await user.save();

      const { user: result1 } = await User.authenticate()('user', 'WRONGpassword');
      expect(result1).to.be.false;

      const { user: result2 } = await User.authenticate()('user', 'WRONGpassword');
      expect(result2).to.be.false;

      const { user: result3 } = await User.authenticate()('user', 'WRONGpassword');
      expect(result3).to.be.false;

      // Last login attempt should lock the user!
      const { user: result4 } = await User.authenticate()('user', 'password');
      expect(result4).to.be.false;
    });

    it('should completely lock account after too many failed attempts', async () => {
      const UserSchema = new Schema({});
      UserSchema.plugin(passportLocalMongoose, {
        limitAttempts: true,
        maxInterval: 1, // Don't require more than a millisecond of waiting
        maxAttempts: 3,
      });

      const User = mongoose.model('LockUserPermanentlyAfterLimitAttemptsAsync', UserSchema);

      const user = new User({ username: 'user' });
      await user.setPassword('password');
      await user.save();

      const { user: user1, error: error1 } = await User.authenticate()('user', 'WRONGpassword');
      expect(user1).to.be.false;
      expect(error1!.message).to.not.contain('locked');

      const { user: user2, error: error2 } = await User.authenticate()('user', 'WRONGpassword');
      expect(user2).to.be.false;
      expect(error2!.message).to.not.contain('locked');

      const { user: user3, error: error3 } = await User.authenticate()('user', 'WRONGpassword');
      expect(user3).to.be.false;
      expect(error3!.message).to.contain('locked');

      await user.resetAttempts!();

      // User should be unlocked
      const { user: user5 } = await User.authenticate()('user', 'password');
      expect(user5).to.exist;
    });

    it('should auto unlock account after unlock interval is reached', async () => {
      const UserSchema = new Schema({});
      UserSchema.plugin(passportLocalMongoose, {
        limitAttempts: true,
        maxInterval: 1, // Don't require more than a millisecond of waiting
        maxAttempts: 3,
        unlockInterval: 1000,
      });

      const User = mongoose.model('AutoUnLockUserAfterUnlockInterverIsReachedAsync', UserSchema);

      const user = new User({ username: 'user' });
      await user.setPassword('password');
      await user.save();

      const { user: user1, error: error1 } = await User.authenticate()('user', 'WRONGpassword');
      expect(user1).to.be.false;
      expect(error1!.message).to.not.contain('locked');

      const { user: user2, error: error2 } = await User.authenticate()('user', 'WRONGpassword');
      expect(user2).to.be.false;
      expect(error2!.message).to.not.contain('locked');

      const { user: user3, error: error3 } = await User.authenticate()('user', 'WRONGpassword');
      expect(user3).to.be.false;
      expect(error3!.message).to.contain('locked');

      function timeout(ms: number) {
        return new Promise((resolve) => setTimeout(resolve, ms));
      }
      await timeout(1000);

      // User should be unlocked
      const { user: user5 } = await User.authenticate()('user', 'password');
      expect(user5).to.not.be.false;
      expect(user5).to.exist;
    });
  });

  describe('static #serializeUser()', function () {
    it('should define a static serializeUser function for passport', function () {
      expect(DefaultUser.serializeUser).to.exist;
    });

    it('should serialize existing user by username field', async function () {
      const user = new DefaultUser({ username: 'user' });

      const username = await usingPromise((cb) => {
        DefaultUser.serializeUser()(user, cb);
      });

      expect(username).to.equal('user');
    });

    it('should serialize existing user by username field override', async () => {
      const UserSchema = new Schema();
      UserSchema.plugin(passportLocalMongoose, { usernameField: 'email' });
      const User = mongoose.model('SerializeUserWithOverride', UserSchema);

      const user = new User({ email: 'emailUsedForUsername' });

      const username = await usingPromise((cb) => {
        User.serializeUser()(user, cb);
      });

      expect(username).to.equal('emailUsedForUsername');
    });
  });

  describe('static #deserializeUser()', function () {
    beforeEach(async () => await dropMongodbCollections(connectionString));
    beforeEach(() => mongoose.connect(connectionString, { bufferCommands: false, autoIndex: false }));
    afterEach(() => mongoose.disconnect());

    it('should define a static deserializeUser function for passport', function () {
      expect(DefaultUser.deserializeUser).to.exist;
    });

    it('should deserialize users by retrieving users from mongodb', async function () {
      const user = await DefaultUser.register({ username: 'user' }, 'password');

      const loadedUser = await usingPromise((cb) => DefaultUser.deserializeUser()('user', cb));
      expect(loadedUser.username).to.equal(user.username);
    });

    it('should deserialize users by retrieving users from mongodb with username override', async () => {
      const UserSchema = new Schema();
      UserSchema.plugin(passportLocalMongoose, { usernameField: 'email' });
      const User = mongoose.model('DeserializeUserWithOverride', UserSchema);

      const email = 'emailUsedForUsername';
      await User.register({ email: email }, 'password');

      const loadedUser = await usingPromise((cb) => {
        User.deserializeUser()(email, cb);
      });
      expect(loadedUser.email).to.equal(email);
    });
  });

  describe('static #findByUsername() async', function () {
    beforeEach(async () => await dropMongodbCollections(connectionString));
    beforeEach(() => mongoose.connect(connectionString, { bufferCommands: false, autoIndex: false }));
    afterEach(() => mongoose.disconnect());

    it('should define static findByUsername helper function', () => {
      const UserSchema = new Schema({});
      UserSchema.plugin(passportLocalMongoose, {});
      const User = mongoose.model('FindByUsernameDefinedAsync', UserSchema);

      expect(User.findByUsername).to.exist;
    });

    it('should retrieve saved user with findByUsername helper function', async () => {
      const UserSchema = new Schema({});
      UserSchema.plugin(passportLocalMongoose, {});
      const User = mongoose.model('FindByUsernameAsync', UserSchema);

      const user = new User({ username: 'hugo' });
      await user.save();

      const foundUser = await User.findByUsername('hugo');

      expect(foundUser).to.exist;
      expect(foundUser!.username).to.equal('hugo');
    });

    it('should return a query object when no callback is specified', async () => {
      const UserSchema = new Schema({});
      UserSchema.plugin(passportLocalMongoose, {});
      const User = mongoose.model('FindByUsernameQueryObjectAsync', UserSchema);

      const user = new User({ username: 'hugo' });
      await user.save();

      const query = User.findByUsername('hugo');

      expect(query).to.exist;

      const foundUser = await query.exec();
      expect(foundUser).to.exist;
      expect(foundUser!.username).to.equal('hugo');
    });

    it('should select all fields', async () => {
      const UserSchema = new Schema({ department: { type: String, required: true } });
      UserSchema.plugin(passportLocalMongoose, {});
      const User = mongoose.model('FindByUsernameWithAllFieldsAsync', UserSchema);

      const user = new User({ username: 'hugo', department: 'DevOps' });
      await user.save();

      const foundUser = await User.findByUsername('hugo');

      expect(foundUser).to.exist;
      expect(foundUser!.username).to.equal('hugo');
      expect(foundUser!.department).to.equal('DevOps');
    });

    it('should select fields specified by selectFields option', async () => {
      const UserSchema = new Schema({ department: { type: String, required: true } });
      UserSchema.plugin(passportLocalMongoose, { selectFields: 'username' });
      const User = mongoose.model('FindByUsernameWithSelectFieldsOptionAsync', UserSchema);

      const user = new User({ username: 'hugo', department: 'DevOps' });
      await user.save();

      const foundUser = await User.findByUsername('hugo');

      expect(foundUser).to.exist;
      expect(foundUser!.username).to.equal('hugo');
      expect(foundUser!.department).to.equal(undefined);
    });

    it('should retrieve saved user with findByUsername helper function with username field override', async () => {
      const UserSchema = new Schema({});
      UserSchema.plugin(passportLocalMongoose, { usernameField: 'email' });
      const User = mongoose.model('FindByUsernameWithOverrideAsync', UserSchema);

      const email = 'emailUsedForUsername';
      const user = new User({ email: email });

      await user.save();
      const foundUser = await User.findByUsername(email);

      expect(foundUser).to.exist;
      expect(foundUser!.email).to.equal(user.email);
    });

    it('should not throw if lowercase option is specified and no username is supplied', async () => {
      const UserSchema = new Schema({});
      UserSchema.plugin(passportLocalMongoose, { usernameLowerCase: true });
      const User = mongoose.model('FindByUsernameWithUndefinedUsernameAsync', UserSchema);

      await User.findByUsername(undefined as any);
    });
  });

  describe('static #register() async', function () {
    beforeEach(async () => await dropMongodbCollections(connectionString));
    beforeEach(() => mongoose.connect(connectionString, { bufferCommands: false, autoIndex: false }));
    afterEach(() => mongoose.disconnect());

    it('should define static register helper function', function () {
      const UserSchema = new Schema({});
      UserSchema.plugin(passportLocalMongoose, {});
      const User = mongoose.model('RegisterDefinedAsync', UserSchema);

      expect(User.register).to.exist;
    });

    it('should register user', async () => {
      const UserSchema = new Schema({});
      UserSchema.plugin(passportLocalMongoose, {});
      const User = mongoose.model('RegisterUserAsync', UserSchema);

      const user = await User.register({ username: 'hugo' }, 'password');
      expect(user).to.exist;

      const foundUser = await User.findByUsername('hugo');
      expect(foundUser).to.exist;
    });

    it('should check for duplicate user name', async () => {
      const UserSchema = new Schema({});
      UserSchema.plugin(passportLocalMongoose, {});
      const User = mongoose.model('RegisterDuplicateUserAsync', UserSchema);

      await User.register({ username: 'hugo' }, 'password');

      try {
        await User.register({ username: 'hugo' }, 'password');
      } catch (_e) {
        return;
      }

      throw new Error('Expected register with duplicate username to throw');
    });

    it('should authenticate registered user', async () => {
      const UserSchema = new Schema({});
      UserSchema.plugin(passportLocalMongoose, { iterations: 1 }); // 1 iteration - safes time in tests
      const User = mongoose.model('RegisterAndAuthenticateUserAsync', UserSchema);

      await User.register({ username: 'hugo' }, 'password');

      const { user, error } = await User.authenticate()('hugo', 'password');

      expect(user).to.exist;
      expect(error).to.not.exist;
    });

    it('should not authenticate registered user with wrong password', async () => {
      const UserSchema = new Schema({});
      UserSchema.plugin(passportLocalMongoose, { iterations: 1 }); // 1 iteration - safes time in tests
      const User = mongoose.model('RegisterAndNotAuthenticateUserAsync', UserSchema);

      await User.register({ username: 'hugo' }, 'password');

      const { user, error } = await User.authenticate()('hugo', 'wrong_password');

      expect(user).to.equal(false);
      expect(error).to.exist;
    });

    it('it should add username existing user without username', async () => {
      const UserSchema = new Schema({});
      UserSchema.plugin(passportLocalMongoose, {});
      const User = mongoose.model('RegisterExistingUserAsync', UserSchema);

      const existingUser = new User({});
      const user = await existingUser.save();
      user.username = 'hugo';

      const registeredUser = await User.register(user, 'password');
      expect(registeredUser).to.exist;

      const foundUser = await User.findByUsername('hugo');
      expect(foundUser).to.exist;
    });

    it('should result in AuthenticationError error in case no username was given', async () => {
      const UserSchema = new Schema({});
      UserSchema.plugin(passportLocalMongoose, {});
      const User = mongoose.model('RegisterUserWithoutUsernameAsync', UserSchema);

      try {
        await User.register({}, 'password');
      } catch (e) {
        expect(e).to.be.instanceof(errors.AuthenticationError);
        return;
      }

      throw new Error('Expected "User.register" to throw');
    });

    it('should result in AuthenticationError error in case no password was given', async () => {
      const UserSchema = new Schema({});
      UserSchema.plugin(passportLocalMongoose, {});
      const User = mongoose.model('RegisterUserWithoutPasswordAsync', UserSchema);

      try {
        await User.register({ username: 'hugo' }, undefined as any);
      } catch (e) {
        expect(e).to.be.instanceof(errors.AuthenticationError);
        return;
      }
    });
  });

  describe('static #createStrategy()', function () {
    it('should create strategy', function () {
      const UserSchema = new Schema({});
      UserSchema.plugin(passportLocalMongoose, { usernameField: 'email' });
      const User = mongoose.model('CreateStrategy', UserSchema);

      const strategy = User.createStrategy();
      expect(strategy).to.exist;
    });
  });
});

async function setPasswordAndAuthenticate(user: any, passwordToSet: string, passwordToAuthenticate: string) {
  await user.setPassword(passwordToSet);
  return await user.authenticate(passwordToAuthenticate);
}

function usingPromise<T>(fn: (cb: (err: any, result?: T) => void) => void): Promise<T> {
  return new Promise((resolve, reject) => {
    fn((err, result) => {
      if (err) {
        return reject(err);
      }
      resolve(result!);
    });
  });
}
