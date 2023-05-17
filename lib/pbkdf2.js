const crypto = require('crypto');

const defaultPasswordHashGeneratorAsync = async (password, options) => {
  const saltBuffer = await new Promise((resolve, reject) =>
    crypto.randomBytes(options.saltlen, (err, saltBuffer) => (err ? reject(err) : resolve(saltBuffer)))
  );

  const salt = saltBuffer.toString(options.encoding);

  const hashBuffer = await new Promise((resolve, reject) =>
    crypto.pbkdf2(password, salt, options.iterations, options.keylen, options.digestAlgorithm, (err, hashBuffer) =>
      err ? reject(err) : resolve(hashBuffer)
    )
  );

  const hash = Buffer.from(hashBuffer, 'binary').toString(options.encoding);

  return { hash, salt };
};

const defaultPasswordHashVerifierAsync = async (password, user, options) => {
  const userHash = user.get(options.hashField);
  const userSalt = user.get(options.saltField);

  const hashBuffer = await new Promise((resolve, reject) =>
    crypto.pbkdf2(password, userSalt, options.iterations, options.keylen, options.digestAlgorithm, (err, hashBuffer) =>
      err ? reject(err) : resolve(hashBuffer)
    )
  );

  return crypto.timingSafeEqual(Buffer.from(userHash, options.encoding), hashBuffer);
};

module.exports = {
  defaultPasswordHashGeneratorAsync,
  defaultPasswordHashVerifierAsync,
};
