var BadRequestError = require('../lib/badrequesterror');
var expect = require('chai').expect;

describe('BadRequestError', function() {
  it('should construct a valid error with stack trace and name', function() {
    var error = new BadRequestError();

    expect(error.stack).to.exist;
    expect(error.name).to.equal('BadRequestError');
  });

  it('should construct a bad request error with message passed', function() {
    var error = new BadRequestError('Test');

    expect(error.message).to.equal('Test');
  });

  it('should construct a bad request error with null message if no message was passed', function() {
    var error = new BadRequestError();

    expect(error.message).to.equal(null);
  });
});
