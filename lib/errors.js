class AuthenticationError extends Error {
  constructor(message) {
    super(message);
    this.name = 'AuthenticationError';
    Error.captureStackTrace(this, this.constructor);
  }
}

class IncorrectUsernameError extends AuthenticationError {
  constructor(message) {
    super(message);
    this.name = 'IncorrectUsernameError';
  }
}

class IncorrectPasswordError extends AuthenticationError {
  constructor(message) {
    super(message);
    this.name = 'IncorrectPasswordError';
  }
}

class MissingUsernameError extends AuthenticationError {
  constructor(message) {
    super(message);
    this.name = 'MissingUsernameError';
  }
}

class MissingPasswordError extends AuthenticationError {
  constructor(message) {
    super(message);
    this.name = 'MissingPasswordError';
  }
}

class UserExistsError extends AuthenticationError {
  constructor(message) {
    super(message);
    this.name = 'UserExistsError';
  }
}

class NoSaltValueStoredError extends AuthenticationError {
  constructor(message) {
    super(message);
    this.name = 'NoSaltValueStoredError';
  }
}

class AttemptTooSoonError extends AuthenticationError {
  constructor(message) {
    super(message);
    this.name = 'AttemptTooSoonError';
  }
}

class TooManyAttemptsError extends AuthenticationError {
  constructor(message) {
    super(message);
    this.name = 'TooManyAttemptsError';
  }
}

module.exports = {
  AuthenticationError,
  IncorrectUsernameError,
  IncorrectPasswordError,
  MissingUsernameError,
  MissingPasswordError,
  UserExistsError,
  NoSaltValueStoredError,
  AttemptTooSoonError,
  TooManyAttemptsError,
};
