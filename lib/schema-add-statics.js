const LocalStrategy = require('passport-local').Strategy;

const errors = require('./errors');

module.exports = function addSchemaStatics(schema, options) {
  // Passport Local Interface
  schema.statics.authenticate = function () {
    return (username, password, cb) => {
      const promise = Promise.resolve()
        .then(() => this.findByUsername(username, true))
        .then((user) => {
          if (user) {
            return user.authenticate(password);
          }

          return { user: false, error: new errors.IncorrectUsernameError(options.errorMessages.IncorrectUsernameError) };
        });

      if (!cb) {
        return promise;
      }

      promise.then(({ user, error }) => cb(null, user, error)).catch((err) => cb(err));
    };
  };

  // Passport Interface
  schema.statics.serializeUser = function () {
    return function (user, cb) {
      cb(null, user.get(options.usernameField));
    };
  };

  schema.statics.deserializeUser = function () {
    return (username, cb) => {
      this.findByUsername(username, cb);
    };
  };

  schema.statics.register = function (user, password, cb) {
    // Create an instance of this in case user isn't already an instance
    if (!(user instanceof this)) {
      user = new this(user);
    }

    const promise = Promise.resolve()
      .then(() => {
        if (!user.get(options.usernameField)) {
          throw new errors.MissingUsernameError(options.errorMessages.MissingUsernameError);
        }
      })
      .then(() => this.findByUsername(user.get(options.usernameField)))
      .then((existingUser) => {
        if (existingUser) {
          throw new errors.UserExistsError(options.errorMessages.UserExistsError);
        }
      })
      .then(() => user.setPassword(password))
      .then(() => user.save());

    if (!cb) {
      return promise;
    }

    promise.then((result) => cb(null, result)).catch((err) => cb(err));
  };

  schema.statics.findByUsername = function (username, opts, cb) {
    if (typeof opts === 'function') {
      cb = opts;
      opts = {};
    }

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

    if (cb) {
      query.exec(cb);
      return;
    }

    return query;
  };

  schema.statics.createStrategy = function () {
    return new LocalStrategy(options, this.authenticate());
  };
};
