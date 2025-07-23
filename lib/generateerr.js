/* jshint expr: true */
const util = require('util');

module.exports = function (name, parameters, options) {
  options = options || {};
  options.captureStackTrace = options.captureStackTrace === undefined ? true : false;
  options.inherits = options.inherits || Error;

  const ctor = function () {
    if (!(this instanceof ctor)) {
      const constructorArgs = Array.prototype.slice.call(arguments);
      constructorArgs.unshift(ctor);

      return new (ctor.bind.apply(ctor, constructorArgs))();
    }

    options.inherits.call(this);

    if (options.captureStackTrace) {
      Error.captureStackTrace && Error.captureStackTrace(this, ctor);
    }

    copy(parameters, this);

    const msg = arguments[0];
    if (msg) {
      const args = Array.prototype.slice.call(arguments);

      if (args.length > 1 && typeof args[args.length - 1] == 'object') {
        const instanceParams = args.pop();

        copy(instanceParams, this);
      }

      this.message = util.format.apply(util, args);
    }

    this.name = name;
  };

  util.inherits(ctor, options.inherits);

  return ctor;
};

function copy(from, to) {
  if (from) {
    for (const key in from) {
      // eslint-disable-next-line no-prototype-builtins
      if (from.hasOwnProperty(key)) {
        to[key] = from[key];
      }
    }
  }

  return to;
}
