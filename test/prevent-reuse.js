var mongoose = require('mongoose');
var Schema = mongoose.Schema;
var expect = require('chai').expect;
var passportLocalMongoose = require('../');
var mongotest = require('./helpers/mongotest');
var errors = require('../lib/errors.js');

describe('prevent password reuse', function() {
  beforeEach(mongotest.prepareDb('mongodb://localhost/passportlocalmongoosereuse'));
  afterEach(mongotest.disconnect());

  it('should add a configurable history field', function () {
      var UserSchema = new Schema({});
      UserSchema.plugin(passportLocalMongoose, {preventReuse: 1, historyField: 'myHistory'});
      var User = mongoose.model('PreventReuseConfigurableField', UserSchema);
      var user = new User();
      expect(user.get('myHistory')).to.be.instanceof(Array);
  });

  it('should save old hash/salt pairs', function (done) {
      this.timeout(5000); // Five seconds - mongo db access needed

      var UserSchema = new Schema({});
      UserSchema.plugin(passportLocalMongoose, {preventReuse: 2, iterations: 1});
      var User = mongoose.model('PreventReuseSavesOld', UserSchema);

      User.register({username: 'adrien'}, 'password', function(err, user) {
        expect(user.passHistory.length).to.equal(0);

        var firstHash = user.get('hash'), firstSalt = user.get('salt');

        user.setPassword('password2', function (err2, user2) {
          expect(user.passHistory.length).to.equal(1);
          expect(user2.passHistory[0][0]).to.equal(firstHash);
          expect(user2.passHistory[0][1]).to.equal(firstSalt);

          user.setPassword('password3', function (err3, user3) {
            expect(user.passHistory.length).to.equal(2);
            expect(user.passHistory[1][0]).to.equal(firstHash);
            expect(user.passHistory[1][1]).to.equal(firstSalt);

            user.setPassword('password4', function (err4, user4) {
              expect(user.passHistory.length).to.equal(2); // still just 2
              done();
            });
          });
        });

      });

  });

  it('should work', function (done) {
      this.timeout(5000); // Five seconds - mongo db access needed

      var UserSchema = new Schema({});
      UserSchema.plugin(passportLocalMongoose, {preventReuse: 2, iterations: 1});
      var User = mongoose.model('PreventReuseWorks', UserSchema);

      User.register({username: 'bob'}, 'password', function(err, user) {
        expect(err).to.not.exist;

        user.setPassword('password', function (err2, user2) {
          expect(err2).to.be.instanceof(errors.PasswordReuseError);

          done();
        });
      });

  });

  it('should not expose historyField', function(done) {
    this.timeout(5000); // Five seconds - mongo db access needed

    var UserSchema = new Schema({});
    UserSchema.plugin(passportLocalMongoose, {preventReuse: 2, iterations: 1});
    var User = mongoose.model('PreventReuseNoExposure', UserSchema);

    User.register({username: 'bob'}, 'password', function(err) {
      expect(err).to.not.exist;

      User.findOne({username: 'bob'}, function(err2, user) {
        expect(err2).to.not.exist;

        expect(user.username).to.equal('bob');
        expect(user.passHistory).to.be.undefined;

        done();
      });
    });

  });
});
