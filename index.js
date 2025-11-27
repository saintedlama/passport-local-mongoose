const crypto = require('crypto');
const { promisify } = require('util');
const LocalStrategy = require('passport-local').Strategy;

const pbkdf2 = require('./lib/pbkdf2');
const errors = require('./lib/errors');
const authenticate = require('./lib/authenticate');

const randomBytesAsync = promisify(crypto.randomBytes);

module.exports = function (schema, options) {
  options = options || {};
  options.saltlen = options.saltlen || 32;
  options.iterations = options.iterations || 25000;
  options.keylen = options.keylen || 512;
  options.encoding = options.encoding || 'hex';
  options.digestAlgorithm = options.digestAlgorithm || 'sha256'; // To get a list of supported hashes use crypto.getHashes()

  function defaultPasswordValidator(_password) {
    return Promise.resolve();
  }

  options.passwordValidator = options.passwordValidator || defaultPasswordValidator;

  // Populate field names with defaults if not set
  options.usernameField = options.usernameField || 'username';
  options.usernameUnique = options.usernameUnique === undefined ? true : options.usernameUnique;

  // Populate username query fields with defaults if not set,
  // otherwise add username field to query fields.
  if (options.usernameQueryFields) {
    options.usernameQueryFields.push(options.usernameField);
  } else {
    options.usernameQueryFields = [options.usernameField];
  }

  // option to find username case insensitively
  options.usernameCaseInsensitive = Boolean(options.usernameCaseInsensitive || false);

  // option to convert username to lowercase when finding
  options.usernameLowerCase = options.usernameLowerCase || false;

  options.hashField = options.hashField || 'hash';
  options.saltField = options.saltField || 'salt';

  if (options.limitAttempts) {
    options.lastLoginField = options.lastLoginField || 'last';
    options.attemptsField = options.attemptsField || 'attempts';
    options.interval = options.interval || 100; // 100 ms
    options.maxInterval = options.maxInterval || 300000; // 5 min
    options.maxAttempts = options.maxAttempts || Infinity;
  }

  options.findByUsername =
    options.findByUsername ||
    function (model, queryParameters) {
      return model.findOne(queryParameters);
    };

  options.errorMessages = options.errorMessages || {};
  options.errorMessages.MissingPasswordError = options.errorMessages.MissingPasswordError || 'No password was given';
  options.errorMessages.AttemptTooSoonError = options.errorMessages.AttemptTooSoonError || 'Account is currently locked. Try again later';
  options.errorMessages.TooManyAttemptsError =
    options.errorMessages.TooManyAttemptsError || 'Account locked due to too many failed login attempts';
  options.errorMessages.NoSaltValueStoredError =
    options.errorMessages.NoSaltValueStoredError || 'Authentication not possible. No salt value stored';
  options.errorMessages.IncorrectPasswordError = options.errorMessages.IncorrectPasswordError || 'Password or username is incorrect';
  options.errorMessages.IncorrectUsernameError = options.errorMessages.IncorrectUsernameError || 'Password or username is incorrect';
  options.errorMessages.MissingUsernameError = options.errorMessages.MissingUsernameError || 'No username was given';
  options.errorMessages.UserExistsError = options.errorMessages.UserExistsError || 'A user with the given username is already registered';

  const schemaFields = {};

  if (!schema.path(options.usernameField)) {
    schemaFields[options.usernameField] = { type: String, unique: options.usernameUnique };
  }
  schemaFields[options.hashField] = { type: String, select: false };
  schemaFields[options.saltField] = { type: String, select: false };

  if (options.limitAttempts) {
    schemaFields[options.attemptsField] = { type: Number, default: 0 };
    schemaFields[options.lastLoginField] = { type: Date, default: Date.now };
  }

  schema.add(schemaFields);

  schema.pre('save', function () {
    if (options.usernameLowerCase && this[options.usernameField]) {
      this[options.usernameField] = this[options.usernameField].toLowerCase();
    }
  });

  schema.methods.setPassword = async function (password) {
    if (!password) {
      throw new errors.MissingPasswordError(options.errorMessages.MissingPasswordError);
    }

    await options.passwordValidator(password);

    const saltBuffer = await randomBytesAsync(options.saltlen);
    const salt = saltBuffer.toString(options.encoding);
    this.set(options.saltField, salt);

    const hashRaw = await pbkdf2(password, salt, options);
    this.set(options.hashField, Buffer.from(hashRaw, 'binary').toString(options.encoding));

    return this;
  };

  schema.methods.changePassword = async function (oldPassword, newPassword) {
    if (!oldPassword || !newPassword) {
      throw new errors.MissingPasswordError(options.errorMessages.MissingPasswordError);
    }

    const { user, error } = await this.authenticate(oldPassword);
    if (!user) {
      throw error;
    }

    await this.setPassword(newPassword);
    await this.save();

    return this;
  };

  schema.methods.authenticate = async function (password) {
    if (this.get(options.saltField)) {
      return await authenticate(this, password, options);
    }

    const user = await this.constructor.findByUsername(this.get(options.usernameField), true);
    if (user) {
      return await authenticate(user, password, options);
    }

    return { user: false, error: new errors.IncorrectUsernameError(options.errorMessages.IncorrectUsernameError) };
  };

  if (options.limitAttempts) {
    schema.methods.resetAttempts = async function () {
      this.set(options.attemptsField, 0);
      return await this.save();
    };
  }

  // Passport Local Interface
  schema.statics.authenticate = function () {
    return async (username, password) => {
      const user = await this.findByUsername(username, true);
      if (user) {
        return await user.authenticate(password);
      }

      return { user: false, error: new errors.IncorrectUsernameError(options.errorMessages.IncorrectUsernameError) };
    };
  };

  // Passport Interface
  schema.statics.serializeUser = function () {
    return function (user, cb) {
      cb(null, user.get(options.usernameField));
    };
  };

  schema.statics.deserializeUser = function () {
    return async (username, cb) => {
      try {
        const user = await this.findByUsername(username);
        cb(null, user);
      } catch (err) {
        cb(err);
      }
    };
  };

  schema.statics.register = async function (user, password) {
    // Create an instance of this in case user isn't already an instance
    if (!(user instanceof this)) {
      user = new this(user);
    }

    if (!user.get(options.usernameField)) {
      throw new errors.MissingUsernameError(options.errorMessages.MissingUsernameError);
    }

    const existingUser = await this.findByUsername(user.get(options.usernameField));
    if (existingUser) {
      throw new errors.UserExistsError(options.errorMessages.UserExistsError);
    }

    await user.setPassword(password);
    return await user.save();
  };

  schema.statics.findByUsername = function (username, opts) {
    if (typeof opts == 'boolean') {
      opts = {
        selectHashSaltFields: opts,
      };
    }

    opts = opts || {};
    opts.selectHashSaltFields = !!opts.selectHashSaltFields;

    // if specified, convert the username to lowercase
    if (username !== undefined && options.usernameLowerCase) {
      username = username.toLowerCase();
    }

    // escape regex tokens
    if (username !== undefined && options.usernameCaseInsensitive) {
      username = username.replace(/[!#$()*+\-./:<=>?[\\\]^{|}]/g, '\\$&');
    }

    // Add each username query field
    const queryOrParameters = [];
    for (let i = 0; i < options.usernameQueryFields.length; i++) {
      const parameter = {};
      parameter[options.usernameQueryFields[i]] = options.usernameCaseInsensitive ? new RegExp(`^${username}$`, 'i') : username;
      queryOrParameters.push(parameter);
    }

    const query = options.findByUsername(this, { $or: queryOrParameters });

    if (opts.selectHashSaltFields) {
      query.select('+' + options.hashField + ' +' + options.saltField);
    }

    if (options.selectFields) {
      query.select(options.selectFields);
    }

    if (options.populateFields) {
      query.populate(options.populateFields);
    }

    return query;
  };

  schema.statics.createStrategy = function () {
    return new LocalStrategy(options, this.authenticate());
  };
};

module.exports.errors = errors;
