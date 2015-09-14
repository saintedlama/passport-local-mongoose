var Err = require('../lib/error.js');
var expect = require('chai').expect;

describe('AuthenticationError', function() {
  it('should construct a valid error with stack trace and name', function() {
    var error = new Err.AuthenticationError();

    expect(error.stack).to.exist;
    expect(error.name).to.equal('AuthenticationError');
  });

  it('should construct a bad request error with message passed', function() {
    var error = new Err.AuthenticationError('Test');

    expect(error.message).to.equal('Test');
  });

  it('should construct a bad request error with null message if no message was passed', function() {
    var error = new Err.AuthenticationError();

    expect(error.message).to.equal(null);
  });
});
