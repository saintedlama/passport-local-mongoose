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
    const attempts = user.get(options.attemptsField) || 0;
    const lastLogin = user.get(options.lastLoginField) ? new Date(user.get(options.lastLoginField)).getTime() : 0;
    const attemptsInterval = Math.pow(options.interval, Math.log(attempts + 1));
    const calculatedInterval = attemptsInterval < options.maxInterval ? attemptsInterval : options.maxInterval;

    if (Date.now() - lastLogin < calculatedInterval) {
      user.set(options.lastLoginField, Date.now());
      await user.save();
      return { user: false, error: new errors.AttemptTooSoonError(options.errorMessages.AttemptTooSoonError!) };
    }

    if (attempts >= options.maxAttempts!) {
      if (options.unlockInterval && Date.now() - lastLogin > options.unlockInterval) {
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
      const attempts = (user.get(options.attemptsField) || 0) + 1;
      user.set(options.lastLoginField, Date.now());
      user.set(options.attemptsField, attempts);
      await user.save();

      if (attempts >= options.maxAttempts!) {
        return { user: false, error: new errors.TooManyAttemptsError(options.errorMessages.TooManyAttemptsError!) };
      } else {
        return { user: false, error: new errors.IncorrectPasswordError(options.errorMessages.IncorrectPasswordError!) };
      }
    }

    return { user: false, error: new errors.IncorrectPasswordError(options.errorMessages.IncorrectPasswordError!) };
  }
}
