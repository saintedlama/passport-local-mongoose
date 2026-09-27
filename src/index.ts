import crypto from 'crypto';
import { promisify } from 'util';
import { Strategy as LocalStrategy } from 'passport-local';
import { Schema, Model, Query, SaveOptions } from 'mongoose';

import { pbkdf2 } from './lib/pbkdf2';
import * as errors from './lib/errors';
import { authenticate } from './lib/authenticate';
import {
  PassportLocalMongooseOptions,
  AuthenticationResult,
  FindByUsernameOptions,
  PassportLocalMongooseDocument,
  VerifyCallback,
} from './types';

const randomBytesAsync = promisify(crypto.randomBytes);

function passportLocalMongoose<T extends PassportLocalMongooseDocument = PassportLocalMongooseDocument>(
  schema: Schema<T>,
  options?: PassportLocalMongooseOptions,
): void {
  const opts: Required<PassportLocalMongooseOptions> = {
    saltlen: 32,
    iterations: 25000,
    keylen: 512,
    encoding: 'hex',
    digestAlgorithm: 'sha256',
    generateHash: (password: string, salt: string) => pbkdf2(password, salt, opts),
    usernameField: 'username',
    usernameUnique: true,
    usernameQueryFields: [],
    usernameCaseInsensitive: false,
    usernameLowerCase: false,
    hashField: 'hash',
    saltField: 'salt',
    limitAttempts: false,
    lastLoginField: 'last',
    attemptsField: 'attempts',
    interval: 100,
    maxInterval: 300000,
    maxAttempts: Infinity,
    unlockInterval: undefined as any,
    passwordValidator: (_password: string) => Promise.resolve(),
    findByUsername: (model: any, queryParameters: any) => model.findOne(queryParameters),
    selectFields: undefined as any,
    populateFields: undefined as any,
    errorMessages: {},
    ...options,
  };

  // Set default error messages
  opts.errorMessages.MissingPasswordError = opts.errorMessages.MissingPasswordError || 'No password was given';
  opts.errorMessages.AttemptTooSoonError = opts.errorMessages.AttemptTooSoonError || 'Account is currently locked. Try again later';
  opts.errorMessages.TooManyAttemptsError =
    opts.errorMessages.TooManyAttemptsError || 'Account locked due to too many failed login attempts';
  opts.errorMessages.NoSaltValueStoredError =
    opts.errorMessages.NoSaltValueStoredError || 'Authentication not possible. No salt value stored';
  opts.errorMessages.IncorrectPasswordError = opts.errorMessages.IncorrectPasswordError || 'Password or username is incorrect';
  opts.errorMessages.IncorrectUsernameError = opts.errorMessages.IncorrectUsernameError || 'Password or username is incorrect';
  opts.errorMessages.MissingUsernameError = opts.errorMessages.MissingUsernameError || 'No username was given';
  opts.errorMessages.UserExistsError = opts.errorMessages.UserExistsError || 'A user with the given username is already registered';

  // Populate username query fields
  if (options?.usernameQueryFields) {
    opts.usernameQueryFields.push(...options.usernameQueryFields, opts.usernameField);
  } else {
    opts.usernameQueryFields = [opts.usernameField];
  }

  const schemaFields: Record<string, any> = {};

  if (!schema.path(opts.usernameField)) {
    schemaFields[opts.usernameField] = { type: String, unique: opts.usernameUnique };
  }
  schemaFields[opts.hashField] = { type: String, select: false };
  schemaFields[opts.saltField] = { type: String, select: false };

  if (opts.limitAttempts) {
    schemaFields[opts.attemptsField] = { type: Number, default: 0 };
    schemaFields[opts.lastLoginField] = { type: Date, default: Date.now };
  }

  schema.add(schemaFields as any);

  schema.pre('save', function () {
    if (opts.usernameLowerCase && this.get(opts.usernameField)) {
      this.set(opts.usernameField, this.get(opts.usernameField).toLowerCase());
    }
  });

  schema.methods.setPassword = async function (this: T, password: string): Promise<T> {
    if (!password) {
      throw new errors.MissingPasswordError(opts.errorMessages.MissingPasswordError!);
    }

    await opts.passwordValidator(password);

    const saltBuffer = await randomBytesAsync(opts.saltlen);
    const salt = saltBuffer.toString(opts.encoding);

    this.set(opts.saltField, salt);

    const hashRaw = await opts.generateHash(password, salt);
    this.set(opts.hashField, Buffer.from(hashRaw).toString(opts.encoding));

    return this;
  };

  schema.methods.changePassword = async function (
    this: T,
    oldPassword: string,
    newPassword: string,
    saveOptions?: SaveOptions,
  ): Promise<T> {
    if (!oldPassword || !newPassword) {
      throw new errors.MissingPasswordError(opts.errorMessages.MissingPasswordError!);
    }

    const { user, error } = await this.authenticate(oldPassword);
    if (!user) {
      throw error;
    }

    await this.setPassword(newPassword);
    await this.save(saveOptions);

    return this;
  };

  schema.methods.authenticate = async function (this: T, password: string): Promise<AuthenticationResult<T>> {
    if (this.get(opts.saltField)) {
      return await authenticate(this, password, opts);
    }

    const ThisModel = this.constructor as any;
    const user = await ThisModel.findByUsername(this.get(opts.usernameField), true);
    if (user) {
      return await authenticate(user, password, opts);
    }

    return { user: false, error: new errors.IncorrectUsernameError(opts.errorMessages.IncorrectUsernameError!) };
  };

  if (opts.limitAttempts) {
    schema.methods.resetAttempts = async function (this: T, saveOptions?: SaveOptions): Promise<T> {
      this.set(opts.attemptsField, 0);
      return await this.save(saveOptions);
    };
  }

  schema.statics.authenticate = function (this: Model<T>) {
    return async (username: string, password: string, cb?: VerifyCallback<T>): Promise<AuthenticationResult<T>> => {
      try {
        const user = await (this as any).findByUsername(username, true);

        if (user) {
          const authResult = await authenticate(user, password, opts);
          if (cb) {
            cb(null, authResult.user, authResult.error);
          }
          return authResult;
        } else {
          const authResult: AuthenticationResult<T> = {
            user: false,
            error: new errors.IncorrectUsernameError(opts.errorMessages.IncorrectUsernameError!),
          };
          if (cb) {
            cb(null, authResult.user, authResult.error);
          }
          return authResult;
        }
      } catch (err: any) {
        if (cb) {
          cb(err);
        }
        throw err;
      }
    };
  };

  schema.statics.serializeUser = function () {
    return function (user: T, cb: (err: any, id?: any) => void) {
      try {
        cb(null, user.get(opts.usernameField));
      } catch (err) {
        cb(err);
      }
    };
  };

  schema.statics.deserializeUser = function (this: Model<T>) {
    return async function (this: any, username: string, cb: (err: any, user?: T | null) => void) {
      try {
        const user = await this.findByUsername(username);
        cb(null, user);
      } catch (err) {
        cb(err);
      }
    };
  };

  schema.statics.register = async function (this: Model<T>, user: T | any, password: string, saveOptions?: SaveOptions): Promise<T> {
    // Create an instance of this in case user isn't already an instance
    if (!(user instanceof this)) {
      user = new this(user);
    }

    if (saveOptions?.session) {
      user.$session(saveOptions.session);
    }

    if (!user.get(opts.usernameField)) {
      throw new errors.MissingUsernameError(opts.errorMessages.MissingUsernameError!);
    }

    const findByUsernameOpts: FindByUsernameOptions = {};
    if (saveOptions?.session) {
      findByUsernameOpts.session = saveOptions.session;
    }

    const existingUser = await (this as any).findByUsername(user.get(opts.usernameField), findByUsernameOpts);
    if (existingUser) {
      throw new errors.UserExistsError(opts.errorMessages.UserExistsError!);
    }

    await user.setPassword(password);
    return await user.save(saveOptions);
  };

  schema.statics.findByUsername = function (
    this: Model<T>,
    username: string,
    selectOrOpts?: boolean | FindByUsernameOptions,
  ): Query<T | null, T> {
    let selectOpts: FindByUsernameOptions = {};

    if (typeof selectOrOpts === 'boolean') {
      selectOpts = {
        selectHashSaltFields: selectOrOpts,
      };
    } else if (selectOrOpts) {
      selectOpts = selectOrOpts;
    }

    selectOpts.selectHashSaltFields = !!selectOpts.selectHashSaltFields;

    // if specified, convert the username to lowercase
    let queryUsername = username;
    if (username !== undefined && opts.usernameLowerCase) {
      queryUsername = username.toLowerCase();
    }

    // escape regex tokens
    if (username !== undefined && opts.usernameCaseInsensitive) {
      queryUsername = username.replace(/[!#$()*+\-./:<=>?[\\\]^{|}]/g, '\\$&');
    }

    // Add each username query field
    const queryOrParameters: Record<string, any>[] = [];
    for (let i = 0; i < opts.usernameQueryFields.length; i++) {
      const parameter: Record<string, any> = {};
      parameter[opts.usernameQueryFields[i]] = opts.usernameCaseInsensitive ? new RegExp(`^${queryUsername}$`, 'i') : queryUsername;
      queryOrParameters.push(parameter);
    }

    const query = opts.findByUsername(this as any, { $or: queryOrParameters });

    if (selectOpts.session) {
      query.session(selectOpts.session);
    }

    if (selectOpts.selectHashSaltFields) {
      query.select('+' + opts.hashField + ' +' + opts.saltField);

      if (opts.limitAttempts) {
        query.select('+' + opts.attemptsField + ' +' + opts.lastLoginField);
      }
    }

    if (opts.selectFields) {
      query.select(opts.selectFields);
    }

    if (opts.populateFields) {
      query.populate(opts.populateFields);
    }

    return query as Query<T | null, T>;
  };

  schema.statics.createStrategy = function (): LocalStrategy {
    return new LocalStrategy(opts as any, (this as any).authenticate());
  };
}

passportLocalMongoose.errors = errors;
export default passportLocalMongoose;
export { errors };
export {
  PassportLocalMongooseOptions,
  AuthenticationResult,
  FindByUsernameOptions,
  PassportLocalMongooseDocument,
  PassportLocalMongooseModel,
} from './types';
