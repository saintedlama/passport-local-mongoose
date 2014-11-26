var util = require('util');

function BadRequestError(message) {
    Error.call(this);
    Error.captureStackTrace(this, arguments.callee);
    this.name = 'BadRequestError';
    this.message = message || null;
}

util.inherits(BadRequestError, Error);

module.exports = BadRequestError;
