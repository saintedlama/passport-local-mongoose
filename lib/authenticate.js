const scmp = require('scmp');

const pbkdf2 = require('./pbkdf2');
const errors = require('./errors');

module.exports = async function authenticate(user, password, options) {
  if (options.limitAttempts) {
    const attemptsInterval = Math.pow(options.interval, Math.log(user.get(options.attemptsField) + 1));
    const calculatedInterval = attemptsInterval < options.maxInterval ? attemptsInterval : options.maxInterval;

    if (Date.now() - user.get(options.lastLoginField) < calculatedInterval) {
      user.set(options.lastLoginField, Date.now());
      await user.save();
      return { user: false, error: new errors.AttemptTooSoonError(options.errorMessages.AttemptTooSoonError) };
    }

    if (user.get(options.attemptsField) >= options.maxAttempts) {
      if (options.unlockInterval && Date.now() - user.get(options.lastLoginField) > options.unlockInterval) {
        user.set(options.lastLoginField, Date.now());
        user.set(options.attemptsField, 0);
        await user.save();
      } else {
        return { user: false, error: new errors.TooManyAttemptsError(options.errorMessages.TooManyAttemptsError) };
      }
    }
  }

  if (!user.get(options.saltField)) {
    return { user: false, error: new errors.NoSaltValueStoredError(options.errorMessages.NoSaltValueStoredError) };
  }

  const hashBuffer = await pbkdf2(password, user.get(options.saltField), options);

  if (scmp(hashBuffer, Buffer.from(user.get(options.hashField), options.encoding))) {
    if (options.limitAttempts) {
      user.set(options.lastLoginField, Date.now());
      user.set(options.attemptsField, 0);
      await user.save();
    }
    return { user, error: undefined };
  } else {
    if (options.limitAttempts) {
      user.set(options.lastLoginField, Date.now());
      user.set(options.attemptsField, user.get(options.attemptsField) + 1);
      await user.save();

      if (user.get(options.attemptsField) >= options.maxAttempts) {
        return { user: false, error: new errors.TooManyAttemptsError(options.errorMessages.TooManyAttemptsError) };
      } else {
        return { user: false, error: new errors.IncorrectPasswordError(options.errorMessages.IncorrectPasswordError) };
      }
    } else {
      return { user: false, error: new errors.IncorrectPasswordError(options.errorMessages.IncorrectPasswordError) };
    }
  }
};
