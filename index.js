"use strict";
const crypto = require('crypto');
const LocalStrategy = require('passport-local').Strategy;

const pbkdf2 = require('./lib/pbkdf2');
const errors = require('./lib/errors');
const authenticate = require('./lib/authenticate');

module.exports = function(schema, options) {
  options = options || {};
  options.saltlen = options.saltlen || 32;
  options.iterations = options.iterations || 25000;
  options.keylen = options.keylen || 512;
  options.encoding = options.encoding || 'hex';
  options.digestAlgorithm = options.digestAlgorithm || 'sha256'; // To get a list of supported hashes use crypto.getHashes()
  options.passwordValidator = options.passwordValidator || function(password, cb) { cb(null); };

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

  options.findByUsername = options.findByUsername || function(model, queryParameters) { return model.findOne(queryParameters); }

  options.errorMessages = options.errorMessages || {};
  options.errorMessages.MissingPasswordError = options.errorMessages.MissingPasswordError || 'No password was given';
  options.errorMessages.AttemptTooSoonError = options.errorMessages.AttemptTooSoonError || 'Account is currently locked. Try again later';
  options.errorMessages.TooManyAttemptsError = options.errorMessages.TooManyAttemptsError || 'Account locked due to too many failed login attempts';
  options.errorMessages.NoSaltValueStoredError = options.errorMessages.NoSaltValueStoredError || 'Authentication not possible. No salt value stored';
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

  schema.pre('save', function(next) {
    if (options.usernameLowerCase && this[options.usernameField]) {
      this[options.usernameField] = this[options.usernameField].toLowerCase();
    }

    next();
  });

  schema.methods.setPassword = function(password, cb) {
    if (!password) {
      return cb(new errors.MissingPasswordError(options.errorMessages.MissingPasswordError));
    }

    options.passwordValidator(password, (err) => {
      if (err) { return cb(err); }

      crypto.randomBytes(options.saltlen, (randomBytesErr, buf) => {
        if (randomBytesErr) {
          return cb(randomBytesErr);
        }

        const salt = buf.toString(options.encoding);

        pbkdf2(password, salt, options, (pbkdf2Err, hashRaw) => {
          if (pbkdf2Err) {
            return cb(pbkdf2Err);
          }

          this.set(options.hashField, new Buffer(hashRaw, 'binary').toString(options.encoding));
          this.set(options.saltField, salt);

          cb(null, this);
        });
      });
    });
  };

  schema.methods.changePassword = function(oldPassword, newPassword, cb) {
    if (!oldPassword || !newPassword) {
      return cb(new errors.MissingPasswordError(options.errorMessages.MissingPasswordError));
    }

    this.authenticate(oldPassword, (err, authenticated) => {
      if (err) { return cb(err); }

      if (!authenticated) {
        return cb(new errors.IncorrectPasswordError(options.errorMessages.IncorrectPasswordError));
      }

      this.setPassword(newPassword, (setPasswordErr, user) => {
        if (setPasswordErr) { return cb(setPasswordErr); }

        this.save(function(saveErr) {
          if (saveErr) { return cb(saveErr); }

          cb(null, user);
        });
      });
    });
  };

  schema.methods.authenticate = function(password, cb) {
    // With hash/salt marked as "select: false" - load model including the salt/hash fields form db and authenticate
    if (!this.get(options.saltField)) {
      this.constructor.findByUsername(this.get(options.usernameField), true, (err, user) => {
        if (err) { return cb(err); }

        if (user) {
          return authenticate(user, password, options, cb);
        } else {
          return cb(null, false, new errors.IncorrectUsernameError(options.errorMessages.IncorrectUsernameError));
        }
      });
    } else {
      return authenticate(this, password, options, cb);
    }
  };

  if (options.limitAttempts) {
    schema.methods.resetAttempts = function(cb) {
      this.set(options.attemptsField, 0);
      this.save(cb);
    };
  }

  schema.statics.authenticate = function() {
    return (username, password, cb) => {
      this.findByUsername(username, true, (err, user) => {
        if (err) { return cb(err); }

        if (user) {
          return user.authenticate(password, cb);
        } else {
          return cb(null, false, new errors.IncorrectUsernameError(options.errorMessages.IncorrectUsernameError));
        }
      });
    };
  };

  schema.statics.serializeUser = function() {
    return function(user, cb) {
      cb(null, user.get(options.usernameField));
    };
  };

  schema.statics.deserializeUser = function() {
    return (username, cb) => {
      this.findByUsername(username, cb);
    };
  };

  schema.statics.register = function(user, password, cb) {
    // Create an instance of this in case user isn't already an instance
    if (!(user instanceof this)) {
      user = new this(user);
    }

    if (!user.get(options.usernameField)) {
      return cb(new errors.MissingUsernameError(options.errorMessages.MissingUsernameError));
    }

    this.findByUsername(user.get(options.usernameField), (err, existingUser) => {
      if (err) { return cb(err); }

      if (existingUser) {
        return cb(new errors.UserExistsError(options.errorMessages.UserExistsError));
      }

      user.setPassword(password, function(setPasswordErr, user) {
        if (setPasswordErr) { return cb(setPasswordErr); }

        user.save(function(saveErr) {
          if (saveErr) { return cb(saveErr); }

          cb(null, user);
        });
      });
    });
  };

  schema.statics.findByUsername = function(username, selectHashSaltFields, cb) {
    if (typeof cb === 'undefined') {
      cb = selectHashSaltFields;
      selectHashSaltFields = false;
    }

    // if specified, convert the username to lowercase
    if (username !== undefined && options.usernameLowerCase) {
      username = username.toLowerCase();
    }

    // Add each username query field
    const queryOrParameters = [];
    for (let i = 0; i < options.usernameQueryFields.length; i++) {
      const parameter = {};
      parameter[options.usernameQueryFields[i]] = options.usernameCaseInsensitive ? new RegExp(`^${username}$`, `i`) : username;
      queryOrParameters.push(parameter);
    }

    const query = options.findByUsername(this, { $or: queryOrParameters });

    if (selectHashSaltFields) {
      query.select('+' + options.hashField + " +" + options.saltField);
    }

    if (options.selectFields) {
      query.select(options.selectFields);
    }

    if (options.populateFields) {
      query.populate(options.populateFields);
    }

    if (cb) {
      query.exec(cb);
    } else {
      return query;
    }
  };

  schema.statics.createStrategy = function() {
    return new LocalStrategy(options, this.authenticate());
  };
};

module.exports.errors = errors;
