# Passport-Local Mongoose
Passport-Local Mongoose is a [Mongoose](http://mongoosejs.com/) [plugin](http://mongoosejs.com/docs/plugins.html) 
that simplifies building username and password login with [Passport](http://passportjs.org).

## Installation

    $ npm install passport-local-mongoose

Passport-Local Mongoose does not require `passport`, `passport-local` or `mongoose` dependencies directly but expects you
to have these dependencies installed.

## Usage

### Plugin Passport-Local Mongoose
First you need to plugin Passport-Local Mongoose into your User schema

    var mongoose = require('mongoose'),
        Schema = mongoose.Schema,
        passportLocalMongoose = require('../lib/passport-local-mongoose.js');
    
    var User = new Schema({});
    
    User.plugin(passportLocalMongoose);
    
    module.exports = mongoose.model('User', User);

You're free to define your User how you like. Passport-Local Mongoose will add a username, hash and salt field to store
the username, the hashed password and the salt value.

Additionally Passport-Local Mongoose adds these methods to your Schema.

#### Instance methods
* setPassword(password, cb) asynchronous method to set a user's password hash and salt
* authenticate(password, cb) asynchronous method to authenticate a user instance

#### Static methods
* authenticate() Generates a function that is used in Passport's LocalStrategy
* serializeUser() Generates a function that is used by Passport to serialize users into the session
* deserializeUser() Generates a function that is used by Passport to deserialize users into the session

### Configure Passport/Passport-Local
You should configure Passport/Passport-Local as described in [the Passport Guide](http://passportjs.org/guide/configure/).

Passport-Local Mongoose supports this setup by implementing a `LocalStrategy` and serializeUser/deserializeUser functions.

To setup Passport-Local Mongoose use this code

    var Account = require('./models/account');
    
    passport.use(new LocalStrategy(Account.authenticate()));
    
    passport.serializeUser(Account.serializeUser());
    passport.deserializeUser(Account.deserializeUser());

Make sure that you have mongoose connected and you're done.

### Examples
For a complete example implementing a registration, login and logout see the 
[login example](https://github.com/saintedlama/passport-local-mongoose/tree/master/examples/login).