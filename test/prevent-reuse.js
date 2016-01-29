var mongoose = require('mongoose');
var Schema = mongoose.Schema;
var expect = require('chai').expect;
var passportLocalMongoose = require('../');
var mongotest = require('./helpers/mongotest');

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
      this.timeout(5000); // Five seconds - heavy crypto in background

      var UserSchema = new Schema({});
      UserSchema.plugin(passportLocalMongoose, {preventReuse: 2});
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

});
