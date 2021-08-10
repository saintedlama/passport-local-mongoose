const errors = require('./lib/errors');
const validateOptions = require('./lib/options-validator');
const addSchemaFields = require('./lib/schema-add-fields');
const addSchemaHooks = require('./lib/schema-add-hooks');
const addSchemaMethods = require('./lib/schema-add-methods');
const addSchemaStatics = require('./lib/schema-add-statics');

module.exports = function (schema, inputOptions) {
  const options = validateOptions(inputOptions);

  addSchemaFields(schema, options);

  addSchemaHooks(schema, options);

  addSchemaMethods(schema, options);

  addSchemaStatics(schema, options);
};

module.exports.errors = errors;
