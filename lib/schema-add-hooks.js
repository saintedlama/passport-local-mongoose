module.exports = function (schema, options) {
  schema.pre('save', function (next) {
    if (options.usernameLowerCase && this[options.usernameField]) {
      this[options.usernameField] = this[options.usernameField].toLowerCase();
    }

    next();
  });
};
