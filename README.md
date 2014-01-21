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

Additionally Passport-Local Mongoose adds some methods to your Schema. See the API Documentation section for more details.

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

#### Simplified Passport/Passport-Local Configuration
Starting with version 0.2.1 passport-local-mongoose adds a helper method `createStrategy` as static method to your schema.
The `createStrategy` is responsible to setup passport-local `LocalStrategy` with the correct options.

    var User = require('./models/user');
    
    // CHANGE: USE "createStrategy" INSTEAD OF "authenticate"
    passport.use(User.createStrategy());
    
    passport.serializeUser(User.serializeUser());
    passport.deserializeUser(User.deserializeUser());

The reason for this functionality is that when using the `usernameField` option to specify an alternative usernameField name, 
for example "email" passport-local would still expect your frontend login form to contain an input field with name "username"
instead of email. This can be configured for passport-local but this is double the work. So we got this shortcut implemented.

### Options
When plugging in Passport-Local Mongoose plugin additional options can be provided to configure
the hashing algorithm.

    User.plugin(passportLocalMongoose, options);

__Main Options__

* saltlen: specifies the salt length in bytes. Default: 32
* iterations: specifies the number of iterations used in pbkdf2 hashing algorithm. Default: 25000
* keylen: specifies the length in byte of the generated key. Default: 512
* usernameField: specifies the field name that holds the username. Defaults to 'username'. This option can be used if you want to use a different 
field to hold the username for example "email".
* saltField: specifies the field name that holds the salt value. Defaults to 'salt'.
* hashField: specifies the field name that holds the password hash value. Defaults to 'hash'.
* selectFields: specifies the fields of the model to be selected from mongodb (and stored in the session). Defaults to 'undefined' so that all fields of the model are selected.
* usernameLowerCase: convert username field value to lower case when saving an querying. Defaults to 'false'.
* populateFields: specifies fields to populate in findByUsername function. Defaults to 'undefined'.
* encoding: specifies the encoding the generated salt and hash will be stored in. Defaults to 'hex'.

__Error Message Options__

* incorrectPasswordError: specifies the error message returned when the password is incorrect. Defaults to 'Incorrect password'.
* incorrectUsernameError: specifies the error message returned when the username is incorrect. Defaults to 'Incorrect username'.
* missingUsernameError: specifies the error message returned when the username has not been set during registration. Defaults to 'Field %s is not set'.
* missingPasswordError: specifies the error message returned when the password has not been set during registration. Defaults to 'Password argument not set!'.
* userExistsError: specifies the error message returned when the user already exists during registration. Defaults to 'User already exists with name %s'.
* noSaltValueStored: specifies the error message returned in case no salt value is stored in the mongodb collection. Defaults to 'Authentication not possible. No salt value stored in mongodb collection!'

*Attention!* Changing any of the hashing options (saltlen, iterations or keylen) in a production environment will prevent that existing users to authenticate!

### Hash Algorithm
Passport-Local Mongoose use the pbkdf2 algorithm of the node crypto library. 
[Pbkdf2](http://en.wikipedia.org/wiki/PBKDF2) was chosen because platform independent
(in contrary to bcrypt). For every user a generated salt value is saved to make
rainbow table attacks even harder.

### Examples
For a complete example implementing a registration, login and logout see the 
[login example](https://github.com/saintedlama/passport-local-mongoose/tree/master/examples/login).

## API Documentation
### Instance methods
* setPassword(password, cb) asynchronous method to set a user's password hash and salt
* authenticate(password, cb) asynchronous method to authenticate a user instance

Using `setPassword()` will only update the document's password fields, but will not save the document.
To commit the changed document, remember to use Mongoose's `document.save()` after using `setPassword()`.

### Static methods
* authenticate() Generates a function that is used in Passport's LocalStrategy
* serializeUser() Generates a function that is used by Passport to serialize users into the session
* deserializeUser() Generates a function that is used by Passport to deserialize users into the session
* register(user, password, cb) Convenience method to register a new user instance with a given password. Checks if username is unique. See [login example](https://github.com/saintedlama/passport-local-mongoose/tree/master/examples/login).
* findByUsername() Convenience method to find a user instance by it's unique username.
* createStrategy() Creates a configured passport-local `LocalStrategy` instance that can be used in passport.

## License
Passport-Local Mongoose is licenses under the [MIT license](http://opensource.org/licenses/MIT).
