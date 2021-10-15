function defaultPasswordValidator(password, cb) {
  // no validation, returns a non error result
  cb(null);
}

function createPasswordValidatorAsync(passwordValidator) {
  return function (password) {
    return new Promise((resolve, reject) => {
      passwordValidator(password, (err) => (err ? reject(err) : resolve()));
    });
  };
}

function defaultFindByUsername(model, queryParameters) {
  return model.findOne(queryParameters);
}

const defaultOptions = {
  saltlen: 32,
  iterations: 25000,
  keylen: 512,
  encoding: 'hex',
  digestAlgorithm: 'sha256',
  passwordValidator: defaultPasswordValidator,
  usernameField: 'username',
  usernameUnique: true,
  usernameCaseInsensitive: false,
  usernameLowerCase: false,
  hashField: 'hash',
  saltField: 'salt',
  limitAttempts: false,
  findByUsername: defaultFindByUsername,
};

const defaultLimitAttemptOptions = {
  lastLoginField: 'last',
  attemptsField: 'attempts',
  interval: 100, // 100 ms
  maxInterval: 5 * 60 * 1000, // 5 min
  maxAttempts: Infinity,
};

const defaultErrorMessages = {
  MissingPasswordError: 'No password was given',
  AttemptTooSoonError: 'Account is currently locked. Try again later',
  TooManyAttemptsError: 'Account locked due to too many failed login attempts',
  NoSaltValueStoredError: 'Authentication not possible. No salt value stored',
  IncorrectPasswordError: 'Password or username is incorrect',
  IncorrectUsernameError: 'Password or username is incorrect',
  MissingUsernameError: 'No username was given',
  UserExistsError: 'A user with the given username is already registered',
};

module.exports = function (inputOptions = {}) {
  // If limiting attempts, ensure all required fields are set
  const options = inputOptions.limitAttempts
    ? Object.assign({}, defaultOptions, defaultLimitAttemptOptions, inputOptions)
    : Object.assign({}, defaultOptions, inputOptions);

  // Create Async password validator if not set
  options.passwordValidatorAsync = options.passwordValidatorAsync || createPasswordValidatorAsync(options.passwordValidator);

  // Populate username query fields with defaults if not set,
  // otherwise add username field to query fields.
  if (Array.isArray(options.usernameQueryFields)) {
    options.usernameQueryFields.push(options.usernameField);
  } else {
    options.usernameQueryFields = [options.usernameField];
  }

  // Set error messages to defaults if not set
  options.errorMessages = Object.assign({}, defaultErrorMessages, options.errorMessages);

  return options;
};
