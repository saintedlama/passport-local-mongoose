4.4.0 / 2017-10-25
==================

  * 4.4.0
  * Merge pull request [#233](https://github.com/saintedlama/passport-local-mongoose/issues/233) from 4umfreak/master
    Issue [#79](https://github.com/saintedlama/passport-local-mongoose/issues/79) and Bug [#58](https://github.com/saintedlama/passport-local-mongoose/issues/58), handle save() asynchronously
  * Update changelog

4.3.0 / 2017-10-25
==================

  * 4.3.0
  * Merge pull request [#234](https://github.com/saintedlama/passport-local-mongoose/issues/234) from MeestorHok/master
    Fixed vulnerable dependency
  * Fixed vulnerable dependency
  * fixed up code tabbing style differences
  * added code and tests to handle mongoose errors and concurrency gracefully.

4.2.1 / 2017-08-26
==================

  * 4.2.1
  * Revert setting hash and salt to null in model since this is a breaking change with possibly the implication to loos credentials in a running system
  * Remove superfluous parameters and ;

4.2.0 / 2017-08-24
==================

  * 4.2.0
  * Remove methuselah aged node.js versions 0.10 and 0.12 from travis build matrix
  * Correct test to check that salt and hash are null
  * Merge branch 'master' of github.com:saintedlama/passport-local-mongoose
  * Implement findByUsername option. Fixes [#227](https://github.com/saintedlama/passport-local-mongoose/issues/227)
  * Move function setPasswordAndAuthenticate to end of file
  * Merge pull request [#226](https://github.com/saintedlama/passport-local-mongoose/issues/226) from guoyunhe/patch-1
    Hide hash and salt fields of user in register()
  * Change undefined to null
  * Hide hash and salt of user in authenticate callback
    After authentication, salt and hash are usually not used anymore. It is better to drop them to avoid exposing in `req.user`
  * Hide hash and salt fields of user in register()
    Usually, in `register()` callback, you do not need salt and hash anymore. They should be hidden to avoid exposing to API.

4.1.0 / 2017-08-08
==================

  * 4.1.0
  * Move to nyc for coverage
  * Adapt change password functionality and tests
  * Refactor authenticate function to its own module
  * Merge pull request [#128](https://github.com/saintedlama/passport-local-mongoose/issues/128) from Gentlee/change-password
    Implement changePassword method [#127](https://github.com/saintedlama/passport-local-mongoose/issues/127)
  * Merge pull request [#140](https://github.com/saintedlama/passport-local-mongoose/issues/140) from AshfordN/patch-2
    Update index.js
  * Add syntax highlighting to code examples
  * Modernize example code by using single line variable declarations and const
  * Refactor pbkdf2 adapter to a module of its own
  * Update dependencies
  * Update build matrix to test against node 7, 8 and mongodb 3.4
  * Compare fields and not object to avoid fields added by mongoose to break the build
  * Downgrade to cross-env ^2.0.0.0 to run tests on node 0.10 and 0.12
  * Update dependencies and adapt code to pass buffers to scmp 2
  * Set timeout to 5000ms for all tests
  * Use the ^ semver operator instead of 4.5.x operator
  * Update dependencies and add debug dependency
  * Minor code style fixes
  * Migrate from assert to chai.expect
  * Retry dropping mongodb collections
    Implementation works around a mongoose issue that background indexes are created while trying to drop a collection
  * Migrate to chai.expect
  * Migrate to chai.expect and cleanup code
  * Rename test "error" to "errors" to match tested file
  * Update index.js
    Corrected Grammatical error in the IncorrectUsernameError and IncorrectUsernameError messages
  * Simplify .travis.yml by moving dependencies required for coverage to dev dependencies
  * Adapt .travis.yml to new container based infrastructure
  * Fix output handling in shelljs 0.7
  * Use cross-env for cross platform tests
  * if user model doesn't include salt/hash, get them from db, change tests timeouts
  * optimize and add test for situation when passwords are the same
  * fix changePassword() test
  * implement changePassword method
  * Merge pull request [#123](https://github.com/saintedlama/passport-local-mongoose/issues/123) from Gentlee/optimize-lowercase
    optimize username lowercasing
  * Remove io.js from build matrix
  * Use travis container-based infrastructure
  * Simplify repository field
  * Use digestAlgorithm sha1 and sha1 generated hash for backward compatibility tests
  * optimize username lowercase
  * Add test to verify that authenticate/hashing is 3.0.0 compatible

4.0.0 / 2016-01-15
==================

  * 4.0.0
  * Revert "Revert "Use semver to do a version check instead of argument length checks""
    This reverts commit e17e720867eb283789d9461ec9b452fb513ee52e.

3.1.2 / 2016-01-15
==================

  * 3.1.2
  * Revert "Use semver to do a version check instead of argument length checks"
    This reverts commit 8732239272636272badcc7e88e0483fdd2be0366.

3.1.1 / 2016-01-15
==================

  * 3.1.1
  * Run tests against latest 4.x and latest 5.x versions
  * Use semver to do a version check instead of argument length checks
  * Update changelog

3.1.0 / 2015-10-05
==================

  * 3.1.0
  * Bring back customizable error messages

3.0.0 / 2015-09-21
==================

  * 3.0.0
  * Make the example depend on the latest npm version
  * Move main file to index.js to simplify the package
  * Refactor error generation and yielding
  * Rename variable Err to errors
  * Move mongotest module to helpers
  * Merge pull request [#105](https://github.com/saintedlama/passport-local-mongoose/issues/105) from opencharterhub/fix/error-handling
    Error handling: Always return instance of 'AuthenticationError'
  * Lint: Add some semicolons
  * Lint: Handle error case
  * Lint: Don't shadow variable names
  * Error handling: Always return instance of 'AuthenticationError'

2.0.0 / 2015-09-14
==================

  * 2.0.0
  * Update changelog
  * Add upgrade warning and document new default digest algorithm
  * Add node.js 4.0.0 as build target
  * Reformat code
  * Add editorconfig
  * Update dependencies

1.3.0 / 2015-09-14
==================

  * 1.3.0
  * Remove superfluous queryParameters declaration
  * Add missing semicolon
  * Merge pull request [#98](https://github.com/saintedlama/passport-local-mongoose/issues/98) from theanimal666/master
    Fix Issue [#96](https://github.com/saintedlama/passport-local-mongoose/issues/96)
  * Replace my tabs with spaces to macth project coding style
  * Support test MongoDB server other then localhost
    Implemented using MONGO_SERVER environment variable
  * Merge remote-tracking branch 'upstream/master'
  * Make authenticate work without salt/hash selected by default
  * Add a generated changelog

1.2.0 / 2015-08-28
==================

  * 1.2.0
