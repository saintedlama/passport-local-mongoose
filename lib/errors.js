var generaterr = require('generaterr');

var AuthenticationError = generaterr('AuthenticationError');

module.exports = {
  AuthenticationError : AuthenticationError,
  IncorrectUsernameError : generaterr('IncorrectUsernameError', null, { inherits : AuthenticationError }),
  IncorrectPasswordError : generaterr('IncorrectPasswordError', null,{ inherits : AuthenticationError }),
  MissingUsernameError : generaterr('MissingUsernameError', null,{ inherits : AuthenticationError }),
  MissingPasswordError : generaterr('MissingPasswordError', null,{ inherits : AuthenticationError }),
  UserExistsError : generaterr('UserExistsError', null,{ inherits : AuthenticationError }),
  NoSaltValueStoredError : generaterr('NoSaltValueStoredError', null,{ inherits : AuthenticationError }),
  AttemptTooSoonError : generaterr('AttemptTooSoonError', null,{ inherits : AuthenticationError }),
  TooManyAttemptsError : generaterr('TooManyAttemptsError', null,{ inherits : AuthenticationError }),
  PasswordReuseError : generaterr('PasswordReuseError', null,{ inherits : AuthenticationError })
};