var crypto = require('crypto');
var scmp = require('scmp');

var pbkdf2 = require('./pbkdf2');
var errors = require('./errors');

module.exports = function authenticate(user, password, options, cb) {
  if (options.limitAttempts) {
    var attemptsInterval = Math.pow(options.interval, Math.log(user.get(options.attemptsField) + 1));
    var calculatedInterval = (attemptsInterval < options.maxInterval) ? attemptsInterval : options.maxInterval;

    if (Date.now() - user.get(options.lastLoginField) < calculatedInterval) {
      user.set(options.lastLoginField, Date.now());
      user.save(function(saveErr) {
		  if (saveErr) {
            return cb(saveErr);
          }
		  return cb(null, false, new errors.AttemptTooSoonError(options.errorMessages.AttemptTooSoonError));
	  });
	  return;
    }

    if (user.get(options.attemptsField) >= options.maxAttempts) {
      return cb(null, false, new errors.TooManyAttemptsError(options.errorMessages.TooManyAttemptsError));
    }
  }

  if (!user.get(options.saltField)) {
    return cb(null, false, new errors.NoSaltValueStoredError(options.errorMessages.NoSaltValueStoredError));
  }

  pbkdf2(password, user.get(options.saltField), options, function (err, hashBuffer) {
    if (err) {
      return cb(err);
    }

    if (scmp(hashBuffer, new Buffer(user.get(options.hashField), options.encoding))) {
			if (options.limitAttempts) {
				user.set(options.lastLoginField, Date.now());
				user.set(options.attemptsField, 0);
				user.save(function(saveErr, user) {
					if (saveErr) {
				      return cb(saveErr);
				    }
					return cb(null, user);
				});
			} else {
				return cb(null, user);
			}
    } else {
      if (options.limitAttempts) {
        user.set(options.lastLoginField, Date.now());
        user.set(options.attemptsField, user.get(options.attemptsField) + 1);
        user.save(function (saveErr) {
          if (saveErr) {
            return cb(saveErr);
          }
          if (user.get(options.attemptsField) >= options.maxAttempts) {
            return cb(null, false, new errors.TooManyAttemptsError(options.errorMessages.TooManyAttemptsError));
          } else {
            return cb(null, false, new errors.IncorrectPasswordError(options.errorMessages.IncorrectPasswordError));
          }
        });
      } else {
        return cb(null, false, new errors.IncorrectPasswordError(options.errorMessages.IncorrectPasswordError));
      }
    }
  });
}
