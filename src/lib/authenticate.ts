import { timingSafeEqual } from 'crypto';
import { Document } from 'mongoose';

import * as errors from './errors';
import { PassportLocalMongooseOptions, AuthenticationResult } from '../types';

export async function authenticate(
  user: Document,
  password: string,
  options: Required<PassportLocalMongooseOptions>,
): Promise<AuthenticationResult> {
  if (options.limitAttempts) {
    const attemptsInterval = Math.pow(options.interval, Math.log(user.get(options.attemptsField) + 1));
    const calculatedInterval = attemptsInterval < options.maxInterval ? attemptsInterval : options.maxInterval;

    if (Date.now() - user.get(options.lastLoginField) < calculatedInterval) {
      user.set(options.lastLoginField, Date.now());
      await user.save();
      return { user: false, error: new errors.AttemptTooSoonError(options.errorMessages.AttemptTooSoonError!) };
    }

    if (user.get(options.attemptsField) >= options.maxAttempts!) {
      if (options.unlockInterval && Date.now() - user.get(options.lastLoginField) > options.unlockInterval) {
        user.set(options.lastLoginField, Date.now());
        user.set(options.attemptsField, 0);
        await user.save();
      } else {
        return { user: false, error: new errors.TooManyAttemptsError(options.errorMessages.TooManyAttemptsError!) };
      }
    }
  }

  if (!user.get(options.saltField)) {
    return { user: false, error: new errors.NoSaltValueStoredError(options.errorMessages.NoSaltValueStoredError!) };
  }

  const hashBuffer = await options.generateHash(password, user.get(options.saltField));
  const storedHash = Buffer.from(user.get(options.hashField), options.encoding);

  if (timingSafeEqual(hashBuffer, storedHash)) {
    if (options.limitAttempts) {
      user.set(options.lastLoginField, Date.now());
      user.set(options.attemptsField, 0);
      await user.save();
    }
    return { user, error: undefined };
  } else {
    if (options.limitAttempts) {
      user.set(options.lastLoginField, Date.now());
      user.set(options.attemptsField, user.get(options.attemptsField) + 1);
      await user.save();

      if (user.get(options.attemptsField) >= options.maxAttempts!) {
        return { user: false, error: new errors.TooManyAttemptsError(options.errorMessages.TooManyAttemptsError!) };
      } else {
        return { user: false, error: new errors.IncorrectPasswordError(options.errorMessages.IncorrectPasswordError!) };
      }
    }

    return { user: false, error: new errors.IncorrectPasswordError(options.errorMessages.IncorrectPasswordError!) };
  }
}
