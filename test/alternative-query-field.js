const mongoose = require('mongoose');
const Schema = mongoose.Schema;
const dropMongodbCollections = require('drop-mongodb-collections');
const debug = require('debug')('passport:local:mongoose');
const passportLocalMongoose = require('../');

const dbName = 'passportlocalmongoosetests';
let connectionString = `mongodb://localhost:27017/${dbName}`;

if (process.env.MONGO_SERVER) {
  connectionString = connectionString.replace('mongodb://localhost', 'mongodb://' + process.env.MONGO_SERVER);
  debug('Using mongodb server from environment variable %s', connectionString);
}

describe('alternative query field', function () {
  beforeEach(async () => await dropMongodbCollections(connectionString));
  beforeEach(() => mongoose.connect(connectionString, { bufferCommands: false, autoIndex: false }));
  afterEach(() => mongoose.disconnect());

  it('should find an existing user by alternative query field', async () => {
    const UserSchema = new Schema({
      email: String,
    });
    UserSchema.plugin(passportLocalMongoose, { iterations: 1, usernameQueryFields: ['email'] }); // 1 iteration - safes time in tests
    const User = mongoose.model('FindAlternativeQueryField', UserSchema);

    const email = 'hugo@test.org';
    const user = new User({ username: 'hugo', email: email });
    await user.save();

    const foundUser = await User.findByUsername(email);
    expect(foundUser).to.exist;
    expect(foundUser.email).to.equal(email);
  });

  it('should authenticate an existing user by alternative query field', async () => {
    const UserSchema = new Schema({
      email: String,
    });
    UserSchema.plugin(passportLocalMongoose, { iterations: 1, usernameQueryFields: ['email'] }); // 1 iteration - safes time in tests
    const User = mongoose.model('AuthenticateAlternativeQueryField', UserSchema);

    const email = 'hugo@test.org';
    const user = new User({ username: 'hugo', email: email });
    await User.register(user, 'password');

    const { user: authUser, error } = await User.authenticate()('hugo@test.org', 'password');
    expect(authUser).to.exist;
    expect(error).to.not.exist;
  });

  it('should authenticate an existing user by default username field', async () => {
    const UserSchema = new Schema({
      email: String,
    });
    UserSchema.plugin(passportLocalMongoose, { iterations: 1, usernameQueryFields: ['email'] }); // 1 iteration - safes time in tests
    const User = mongoose.model('AuthenticateDefaultField', UserSchema);

    const email = 'hugo@test.org';
    const user = new User({ username: 'hugo', email: email });
    await User.register(user, 'password');

    const { user: authUser, error } = await User.authenticate()('hugo', 'password');
    expect(authUser).to.exist;
    expect(error).to.not.exist;
  });

  it('should not authenticate an existing user by unconfigured alternative query field', async () => {
    const UserSchema = new Schema({
      email: String,
    });

    UserSchema.plugin(passportLocalMongoose, { iterations: 1, usernameQueryFields: [] }); // 1 iteration - safes time in tests
    const User = mongoose.model('NotAuthenticateUnconfiguredAlternativeQueryField', UserSchema);

    const email = 'hugo@test.org';
    const user = new User({ username: 'hugo', email: email });
    await User.register(user, 'password');

    const { user: authUser, error } = await User.authenticate()('hugo@test.org', 'password');
    expect(authUser).to.be.false;
    expect(error).to.exist;
  });
});
