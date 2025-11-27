import { promisify } from 'util';
import crypto from 'crypto';

const pbkdf2Async = promisify(crypto.pbkdf2);

interface Pbkdf2Options {
  iterations: number;
  keylen: number;
  digestAlgorithm: string;
}

export async function pbkdf2(password: string, salt: string, options: Pbkdf2Options): Promise<Buffer> {
  return await pbkdf2Async(password, salt, options.iterations, options.keylen, options.digestAlgorithm);
}
