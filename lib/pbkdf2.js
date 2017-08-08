var crypto = require('crypto');
var semver = require('semver');

var pbkdf2DigestSupport = semver.gte(process.version, '0.12.0');

module.exports = function pbkdf2(password, salt, options, callback) {
  if (pbkdf2DigestSupport) {
    crypto.pbkdf2(password, salt, options.iterations, options.keylen, options.digestAlgorithm, callback);
  } else {
    crypto.pbkdf2(password, salt, options.iterations, options.keylen, callback);
  }
};