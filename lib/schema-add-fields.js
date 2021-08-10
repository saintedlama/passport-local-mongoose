module.exports = function (schema, options) {
  const schemaFields = {};
  if (!schema.path(options.usernameField)) {
    schemaFields[options.usernameField] = { type: String, unique: options.usernameUnique };
  }
  schemaFields[options.hashField] = { type: String, select: false };
  schemaFields[options.saltField] = { type: String, select: false };

  if (options.limitAttempts) {
    schemaFields[options.attemptsField] = { type: Number, default: 0 };
    schemaFields[options.lastLoginField] = { type: Date, default: Date.now };
  }

  schema.add(schemaFields);
};
