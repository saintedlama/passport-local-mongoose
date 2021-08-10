const crypto = require('crypto');

const pbkdf2 = require('./pbkdf2');
const errors = require('./errors');
const authenticate = require('./authenticate');

function pbkdf2Promisified(password, salt, options) {
  return new Promise((resolve, reject) => pbkdf2(password, salt, options, (err, hashRaw) => (err ? reject(err) : resolve(hashRaw))));
}

function randomBytes(saltlen) {
  return new Promise((resolve, reject) => crypto.randomBytes(saltlen, (err, saltBuffer) => (err ? reject(err) : resolve(saltBuffer))));
}

module.exports = function addSchemaMethods(schema, options) {
  schema.methods.setPassword = function (password, cb) {
    const promise = Promise.resolve()
      .then(() => {
        if (!password) {
          throw new errors.MissingPasswordError(options.errorMessages.MissingPasswordError);
        }
      })
      .then(() => options.passwordValidatorAsync(password))
      .then(() => randomBytes(options.saltlen))
      .then((saltBuffer) => saltBuffer.toString(options.encoding))
      .then((salt) => {
        this.set(options.saltField, salt);

        return salt;
      })
      .then((salt) => pbkdf2Promisified(password, salt, options))
      .then((hashRaw) => {
        this.set(options.hashField, Buffer.from(hashRaw, 'binary').toString(options.encoding));
      })
      .then(() => this);

    if (!cb) {
      return promise;
    }

    promise.then((result) => cb(null, result)).catch((err) => cb(err));
  };

  schema.methods.changePassword = function (oldPassword, newPassword, cb) {
    const promise = Promise.resolve()
      .then(() => {
        if (!oldPassword || !newPassword) {
          throw new errors.MissingPasswordError(options.errorMessages.MissingPasswordError);
        }
      })
      .then(() => this.authenticate(oldPassword))
      .then(({ user }) => {
        if (!user) {
          throw new errors.IncorrectPasswordError(options.errorMessages.IncorrectPasswordError);
        }
      })
      .then(() => this.setPassword(newPassword))
      .then(() => this.save())
      .then(() => this);

    if (!cb) {
      return promise;
    }

    promise.then((result) => cb(null, result)).catch((err) => cb(err));
  };

  schema.methods.authenticate = function (password, cb) {
    const promise = Promise.resolve().then(() => {
      if (this.get(options.saltField)) {
        return authenticate(this, password, options);
      }

      return this.constructor.findByUsername(this.get(options.usernameField), true).then((user) => {
        if (user) {
          return authenticate(user, password, options);
        }

        return { user: false, error: new errors.IncorrectUsernameError(options.errorMessages.IncorrectUsernameError) };
      });
    });

    if (!cb) {
      return promise;
    }

    promise.then(({ user, error }) => cb(null, user, error)).catch((err) => cb(err));
  };

  if (options.limitAttempts) {
    schema.methods.resetAttempts = function (cb) {
      const promise = Promise.resolve().then(() => {
        this.set(options.attemptsField, 0);
        return this.save();
      });

      if (!cb) {
        return promise;
      }

      promise.then((result) => cb(null, result)).catch((err) => cb(err));
    };
  }
};
