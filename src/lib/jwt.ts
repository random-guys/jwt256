import crypto from 'crypto';
import { NextFunction, Request, Response } from 'express';
import { promisify } from 'util';
import { JWT_CACHE_TTL } from './constants';
import httpStatus from 'http-status-codes';
import RedisService from './redis';
import { AES256, JWT } from './utils';

/**
 * Reads the Auth header and AES decrypts the Bearer token to
 * get the JWT token and the user id stored within.
 *
 * It then checks the Redis Service using the `user_id` as key to validate
 *
 * The user ID is stored in `req.user`
 *
 * @param { RedisService } redis Redis Service instance
 */
export const GetUserAuth = (redis: RedisService) => {
  return async (req: Request, res: Response, next: NextFunction) => {
    try {
      const { JWT_SECRET, ENCRYPTION_KEY } = process.env;

      if (!JWT_SECRET) {
        throw new Error('please add JWT_SECRET to the environment variables');
      }

      if (!ENCRYPTION_KEY) {
        throw new Error(
          'please add ENCRYPTION_KEY to the environment variables'
        );
      }

      const jwt: JWT = new JWT(JWT_SECRET);

      const auth = req.headers.authorization;
      if (!auth) throw new Error('Session has expired');
      const auth_key = auth.split(' ')[1];

      // split the keys using the separator
      const keys = auth_key.split('.');
      const cipher = keys[0];
      const tag = keys[2];
      const iv = keys[1];

      const aes = new AES256(Buffer.from(ENCRYPTION_KEY, 'utf8'));
      const plain_text = aes.decrypt(
        cipher,
        Buffer.from(iv, 'hex'),
        Buffer.from(tag, 'hex')
      );

      const token = await jwt.decode(plain_text);
      const user = await redis.get(token.id);
      if (user === auth_key) {
        // Auth was successful
        req.user = token.id;

        // refresh access token
        await redis.set(token.id, auth_key, 'EX', JWT_CACHE_TTL);

        next();
      } else throw new Error('Session has expired');
    } catch (err) {
      return res.status(httpStatus.UNAUTHORIZED).json({
        status: 'error',
        data: null,
        message: err.message,
        code: httpStatus.UNAUTHORIZED
      });
    }
  };
};

/**
 * Creates a JWT token with the user's ID, then AES encrypts the
 * JWT token and saves it in Redis.
 *
 * The method assumes that the `JWT_SECRET` and `ENCRYPTION_KEY` env variables
 * are set.
 *
 * @param { RedisService } redis Redis Service instance
 * @param { string } user_id The user's ID
 * @returns AES encypted cipher text
 */
export const SetUserAuth = async (redis: RedisService, user_id: string) => {
  const { JWT_SECRET, ENCRYPTION_KEY } = process.env;

  if (!JWT_SECRET) {
    throw new Error('please add JWT_SECRET to the environment variables');
  }

  if (!ENCRYPTION_KEY) {
    throw new Error('please add ENCRYPTION_KEY to the environment variables');
  }

  const jwt: JWT = new JWT(JWT_SECRET);

  const genRandomBytes = promisify(crypto.randomBytes);
  const salt = await genRandomBytes(32);
  const token = await jwt.sign({
    id: user_id,
    salt: salt.toString('hex')
  });

  // start encrption
  const aes = new AES256(Buffer.from(ENCRYPTION_KEY, 'utf8'));

  //encrypt token
  const cipher = aes.encrypt(token);
  const iv = cipher.iv.toString('hex');
  const tag = cipher.tag.toString('hex');

  //combine the JWT token and the salt
  const auth_key = `${cipher.enc}.${iv}.${tag}`;

  //cache token in redis
  await redis.set(user_id, auth_key, 'EX', JWT_CACHE_TTL);
  return auth_key;
};

/**
 * Reads the request auth header and AES decrypts the Bearer token to
 * get the JWT token and retuns the user id stored within.
 *
 * @param { Request } req
 * @returns A promise with the user ID
 */
export const GetUserToken = (req: Request): Promise<string> => {
  return new Promise(async (resolve, reject) => {
    try {
      const { JWT_SECRET, ENCRYPTION_KEY } = process.env;

      if (!JWT_SECRET) {
        throw new Error('please add JWT_SECRET to the environment variables');
      }

      if (!ENCRYPTION_KEY) {
        throw new Error(
          'please add ENCRYPTION_KEY to the environment variables'
        );
      }

      const jwt: JWT = new JWT(JWT_SECRET);

      const auth = req.headers.authorization;
      if (!auth) return reject('Missing Auth Header');

      const auth_key = auth.split(' ')[1];
      const keys = auth_key.split('.');
      const cipher = keys[0];
      const tag = keys[2];
      const iv = keys[1];

      const aes = new AES256(Buffer.from(ENCRYPTION_KEY, 'utf8'));
      const plain_text = aes.decrypt(
        cipher,
        Buffer.from(iv, 'hex'),
        Buffer.from(tag, 'hex')
      );

      const token = await jwt.decode(plain_text);
      return resolve(token.id);
    } catch (err) {
      return reject(err);
    }
  });
};
