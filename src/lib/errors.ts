export class AuthenticationError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'AuthenticationError';
    Error.captureStackTrace(this, this.constructor);
  }
}

export class IncorrectUsernameError extends AuthenticationError {
  constructor(message: string) {
    super(message);
    this.name = 'IncorrectUsernameError';
  }
}

export class IncorrectPasswordError extends AuthenticationError {
  constructor(message: string) {
    super(message);
    this.name = 'IncorrectPasswordError';
  }
}

export class MissingUsernameError extends AuthenticationError {
  constructor(message: string) {
    super(message);
    this.name = 'MissingUsernameError';
  }
}

export class MissingPasswordError extends AuthenticationError {
  constructor(message: string) {
    super(message);
    this.name = 'MissingPasswordError';
  }
}

export class UserExistsError extends AuthenticationError {
  constructor(message: string) {
    super(message);
    this.name = 'UserExistsError';
  }
}

export class NoSaltValueStoredError extends AuthenticationError {
  constructor(message: string) {
    super(message);
    this.name = 'NoSaltValueStoredError';
  }
}

export class AttemptTooSoonError extends AuthenticationError {
  constructor(message: string) {
    super(message);
    this.name = 'AttemptTooSoonError';
  }
}

export class TooManyAttemptsError extends AuthenticationError {
  constructor(message: string) {
    super(message);
    this.name = 'TooManyAttemptsError';
  }
}
