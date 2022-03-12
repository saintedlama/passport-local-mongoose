const errors = require('../lib/errors.js');
const expect = require('chai').expect;

describe('AuthenticationError', function () {
  it('should construct a valid error with stack trace and name', function () {
    const error = new errors.AuthenticationError();

    expect(error.stack).to.exist;
    expect(error.name).to.equal('AuthenticationError');
  });

  it('should construct a bad request error with message passed', function () {
    const error = new errors.AuthenticationError('Test');

    expect(error.message).to.equal('Test');
  });

  it('should construct an AuthenticationError with empty message if no message was passed', function () {
    const error = new errors.AuthenticationError();

    expect(error.message).to.equal('');
  });
});
