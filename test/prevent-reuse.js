var mongoose = require('mongoose');
var Schema = mongoose.Schema;
var expect = require('chai').expect;
var passportLocalMongoose = require('../');
var mongotest = require('./helpers/mongotest');

describe('prevent password reuse', function() {
  beforeEach(mongotest.prepareDb('mongodb://localhost/passportlocalmongoosereuse'));
  afterEach(mongotest.disconnect());

  it('should run my additional test', function () {
    expect(true).to.be.true;
  });

});
