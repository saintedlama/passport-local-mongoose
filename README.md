# Passport-Local Mongoose
Passport-Local Mongoose is a [Mongoose](http://mongoosejs.com/) [plugin](http://mongoosejs.com/docs/plugins.html) 
that simplifies building username and password login with [Passport](http://passportjs.org).

[![Build Status](https://travis-ci.org/saintedlama/passport-local-mongoose.png?branch=master)](https://travis-ci.org/saintedlama/passport-local-mongoose)

## Installation

    $ npm install passport-local-mongoose

Passport-Local Mongoose does not require `passport`, `passport-local` or `mongoose` dependencies directly but expects you
to have these dependencies installed.

## Usage

### Plugin Passport-Local Mongoose
First you need to plugin Passport-Local Mongoose into your User schema

    var mongoose = require('mongoose'),
        Schema = mongoose.Schema,
        passportLocalMongoose = require('passport-local-mongoose');
    
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
* register(user, password, cb) Convenience method to register a new user instance with a given password. Checks if username is unique. See [login example](https://github.com/saintedlama/passport-local-mongoose/tree/master/examples/login).
* findByUsername() Convenience method to find a user instance by it's unique username.

### Configure Passport/Passport-Local
You should configure Passport/Passport-Local as described in [the Passport Guide](http://passportjs.org/guide/configure/).

Passport-Local Mongoose supports this setup by implementing a `LocalStrategy` and serializeUser/deserializeUser functions.

To setup Passport-Local Mongoose use this code

    // requires the model with Passport-Local Mongoose plugged in
    var User = require('./models/user');
    
    // use static authenticate method of model in LocalStrategy
    passport.use(new LocalStrategy(User.authenticate()));
    
    // use static serialize and deserialize of model for passport session support
    passport.serializeUser(User.serializeUser());
    passport.deserializeUser(User.deserializeUser());

Make sure that you have mongoose connected and you're done.

### Options
When plugging in Passport-Local Mongoose plugin additional options can be provided to configure
the hashing algorithm.

    User.plugin(passportLocalMongoose, options);

Option keys and defaults
* saltlen: specifies the salt length in bytes. Default: 32
* iterations: specifies the number of iterations used in pbkdf2 hashing algorithm. Default: 25000
* keylen: specifies the length in byte of the generated key. Default: 512
* usernameField: specifies the field name that holds the username. Defaults to 'username'. This option can be used if you want to use a different 
field to hold the username for example "email".
* saltField: specifies the field name that holds the salt value. Defaults to 'salt'.
* hashField: specifies the field name that holds the password hash value. Defaults to 'hash'.

*Attention!* Changing these values for example in a production environment will prevent that existing users can authenticate!

### Hash Algorithm
Passport-Local Mongoose use the pbkdf2 algorithm of the node crypto library. 
[Pbkdf2](http://en.wikipedia.org/wiki/PBKDF2) was choosen because platform independent 
(in contrary to bcrypt). For every user a generated salt value is saved to make
rainbow table attacks even harder.


### Examples
For a complete example implementing a registration, login and logout see the 
[login example](https://github.com/saintedlama/passport-local-mongoose/tree/master/examples/login).