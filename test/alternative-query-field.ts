import { describe, it, expect, beforeEach, afterEach } from 'vitest';

import mongoose, { Schema } from 'mongoose';
import dropMongodbCollections from 'drop-mongodb-collections';
import Debug from 'debug';
import passportLocalMongoose, { PassportLocalMongooseModel, PassportLocalMongooseDocument } from '../src/index.ts';

const debug = Debug('passport:local:mongoose');

const dbName = 'passportlocalmongoosetests';
let connectionString = `mongodb://localhost:27017/${dbName}`;

if (process.env.MONGO_SERVER) {
  connectionString = connectionString.replace('mongodb://localhost', 'mongodb://' + process.env.MONGO_SERVER);
  debug('Using mongodb server from environment variable %s', connectionString);
}

interface UserDocument extends PassportLocalMongooseDocument {
  email?: string;
}

const UserSchema = new Schema<UserDocument>({
  email: String,
});

describe('alternative query field', function () {
  beforeEach(async () => await dropMongodbCollections(connectionString));
  beforeEach(() => mongoose.connect(connectionString, { bufferCommands: false, autoIndex: false }));
  afterEach(() => mongoose.disconnect());

  it('should find an existing user by alternative query field', async () => {
    UserSchema.plugin(passportLocalMongoose, { iterations: 1, usernameQueryFields: ['email'] }); // 1 iteration - safes time in tests
    const User = mongoose.model<UserDocument>('FindAlternativeQueryField', UserSchema) as PassportLocalMongooseModel<UserDocument>;

    const email = 'hugo@test.org';
    const user = new User({ username: 'hugo', email: email });
    await user.save();

    const foundUser = await User.findByUsername(email);
    expect(foundUser).to.exist;
    expect(foundUser!.email).to.equal(email);
  });

  it('should authenticate an existing user by alternative query field', async () => {
    UserSchema.plugin(passportLocalMongoose, { iterations: 1, usernameQueryFields: ['email'] }); // 1 iteration - safes time in tests
    const User = mongoose.model<UserDocument>('AuthenticateAlternativeQueryField', UserSchema) as PassportLocalMongooseModel<UserDocument>;

    const email = 'hugo@test.org';
    const user = new User({ username: 'hugo', email: email });
    await User.register(user, 'password');

    const { user: authUser, error } = await User.authenticate()('hugo@test.org', 'password');
    expect(authUser).to.exist;
    expect(error).to.not.exist;
  });

  it('should authenticate an existing user by default username field', async () => {
    UserSchema.plugin(passportLocalMongoose, { iterations: 1, usernameQueryFields: ['email'] }); // 1 iteration - safes time in tests
    const User = mongoose.model<UserDocument>('AuthenticateDefaultField', UserSchema) as PassportLocalMongooseModel<UserDocument>;

    const email = 'hugo@test.org';
    const user = new User({ username: 'hugo', email: email });
    await User.register(user, 'password');

    const { user: authUser, error } = await User.authenticate()('hugo', 'password');
    expect(authUser).to.exist;
    expect(error).to.not.exist;
  });

  it('should not authenticate an existing user by unconfigured alternative query field', async () => {
    UserSchema.plugin(passportLocalMongoose, { iterations: 1, usernameQueryFields: [] }); // 1 iteration - safes time in tests
    const User = mongoose.model<UserDocument>('NotAuthenticateUnconfiguredAlternativeQueryField', UserSchema) as PassportLocalMongooseModel<UserDocument>;

    const email = 'hugo@test.org';
    const user = new User({ username: 'hugo', email: email });
    await User.register(user, 'password');

    const { user: authUser, error } = await User.authenticate()('hugo@test.org', 'password');
    expect(authUser).to.be.false;
    expect(error).to.exist;
  });
});
