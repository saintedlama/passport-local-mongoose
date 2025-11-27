const { promisify } = require('util');
const crypto = require('crypto');

const pbkdf2Async = promisify(crypto.pbkdf2);

module.exports = async function pbkdf2(password, salt, options) {
  return await pbkdf2Async(password, salt, options.iterations, options.keylen, options.digestAlgorithm);
};
