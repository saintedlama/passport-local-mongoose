import { Document, Model, Query } from 'mongoose';

export interface PassportLocalOptions {
  // Field names
  usernameField?: string;
  hashField?: string;
  saltField?: string;
  usernameQueryFields?: string[];

  // Username options
  usernameUnique?: boolean;
  usernameLowerCase?: boolean;
  usernameCaseInsensitive?: boolean;

  // Password options
  saltlen?: number;
  iterations?: number;
  keylen?: number;
  encoding?: BufferEncoding;
  digestAlgorithm?: string;
  passwordValidator?: (_password: string) => Promise<void>;

  // Rate limiting
  limitAttempts?: boolean;
  maxAttempts?: number;
  interval?: number;
  maxInterval?: number;
  unlockInterval?: number;
  lastLoginField?: string;
  attemptsField?: string;

  // Query options
  findByUsername?: <T extends Document>(_model: Model<T>, _queryParameters: any) => Query<T | null, T>;
  selectFields?: string;
  populateFields?: string;

  // Error messages
  errorMessages?: {
    MissingPasswordError?: string;
    AttemptTooSoonError?: string;
    TooManyAttemptsError?: string;
    NoSaltValueStoredError?: string;
    IncorrectPasswordError?: string;
    IncorrectUsernameError?: string;
    MissingUsernameError?: string;
    UserExistsError?: string;
  };
}

export interface AuthenticationResult<T = any> {
  user: false | T;
  error?: Error;
}

export interface FindByUsernameOptions {
  selectHashSaltFields?: boolean;
}

export interface PassportLocalDocument extends Document {
  setPassword(_password: string): Promise<this>;
  changePassword(_oldPassword: string, _newPassword: string): Promise<this>;
  authenticate(_password: string): Promise<AuthenticationResult<this>>;
  resetAttempts?(): Promise<this>;
}

export interface PassportLocalModel<T extends PassportLocalDocument> extends Model<T> {
  authenticate(): (_username: string, _password: string) => Promise<AuthenticationResult<T>>;
  serializeUser(): (_user: T, _cb: (_err: any, _id?: any) => void) => void;
  deserializeUser(): (_username: string, _cb: (_err: any, _user?: T | null) => void) => void;
  register(_user: T | any, _password: string): Promise<T>;
  findByUsername(_username: string, _selectHashSaltFields?: boolean | FindByUsernameOptions): Query<T | null, T>;
  createStrategy(): any;
}
