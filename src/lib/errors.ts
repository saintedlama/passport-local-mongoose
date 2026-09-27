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
  public retryAfter?: number;
  public attemptsRemaining?: number;

  constructor(message: string, retryAfter?: number, attemptsRemaining?: number) {
    super(message);
    this.name = 'AttemptTooSoonError';
    this.retryAfter = retryAfter;
    this.attemptsRemaining = attemptsRemaining;
  }
}

export class TooManyAttemptsError extends AuthenticationError {
  constructor(message: string) {
    super(message);
    this.name = 'TooManyAttemptsError';
  }
}
