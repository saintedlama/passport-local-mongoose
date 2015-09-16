var util = require('util');

function AuthenticationError(message) {
  this.name = 'AuthenticationError';
  this.message = message || null;
  this.stack = (new Error()).stack;
}

function IncorrectUsernameError(usernameField) {
  this.name = 'IncorrectUsernameError';
  this.message = util.format('Incorrect %s', usernameField);
}

function IncorrectPasswordError() {
  this.name = 'IncorrectPasswordError';
  this.message = 'Incorrect password';
}

function MissingUsernameError(usernameField) {
  this.name = 'MissingUsernameError';
  this.message = util.format('Field %s is not set', usernameField);
}

function MissingPasswordError() {
  this.name = 'MissingPasswordError';
  this.message = util.format('Password argument not set');
}

function UserExistsError(usernameField, usernameValue) {
  this.name = 'UserExistsError';
  this.message = util.format('User already exists with %s %s', usernameField, usernameValue);
}

function NoSaltValueStoredError() {
  this.name = 'NoSaltValueStoredError';
  this.message = util.format('Authentication not possible. No salt value stored in MongoDB collection');
}

function AttemptTooSoonError() {
  this.name = 'AttemptTooSoonError';
  this.message = util.format('Login attempted too soon after previous attempt');
}

function TooManyAttemptsError() {
  this.name = 'TooManyAttemptsError';
  this.message = util.format('Account locked due to too many failed login attempts');
}

util.inherits(AuthenticationError, Error);
util.inherits(IncorrectUsernameError, AuthenticationError);
util.inherits(IncorrectPasswordError, AuthenticationError);
util.inherits(MissingUsernameError, AuthenticationError);
util.inherits(MissingPasswordError, AuthenticationError);
util.inherits(UserExistsError, AuthenticationError);
util.inherits(NoSaltValueStoredError, AuthenticationError);
util.inherits(AttemptTooSoonError, AuthenticationError);
util.inherits(TooManyAttemptsError, AuthenticationError);

module.exports.AuthenticationError = AuthenticationError;
module.exports.IncorrectUsernameError = IncorrectUsernameError;
module.exports.IncorrectPasswordError = IncorrectPasswordError;
module.exports.MissingUsernameError = MissingUsernameError;
module.exports.MissingPasswordError = MissingPasswordError;
module.exports.UserExistsError = UserExistsError;
module.exports.NoSaltValueStoredError = NoSaltValueStoredError;
module.exports.AttemptTooSoonError = AttemptTooSoonError;
module.exports.TooManyAttemptsError = TooManyAttemptsError;

