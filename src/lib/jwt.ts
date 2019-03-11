import crypto from "crypto";
import { NextFunction, Request, Response } from "express";
import { promisify } from "util";
import { JWT_CACHE_TTL } from "./constants";
import httpStatus from "http-status-codes";
import RedisService from "./redis";
import { AES256, JWT } from "./utils";

const GetAuth = (redis: RedisService) => {
  return async (req: Request, res: Response, next: NextFunction) => {
    try {
      const { JWT_SECRET, ENCRYPTION_KEY } = process.env;

      if (!JWT_SECRET) {
        throw new Error("please add JWT_SECRET to the environment variables");
      }

      if (!ENCRYPTION_KEY) {
        throw new Error(
          "please add ENCRYPTION_KEY to the environment variables"
        );
      }

      const jwt: JWT = new JWT(JWT_SECRET);

      const auth = req.headers.authorization;
      if (!auth) throw new Error("Session has expired");
      const auth_key = auth.split(" ")[1];

      // split the keys using the separator
      const keys = auth_key.split(".");
      const cipher = keys[0];
      const tag = keys[2];
      const iv = keys[1];

      const aes = new AES256(Buffer.from(ENCRYPTION_KEY, "utf8"));
      const plain_text = aes.decrypt(
        cipher,
        Buffer.from(iv, "hex"),
        Buffer.from(tag, "hex")
      );

      const token = await jwt.decode(plain_text);
      const user = await redis.get(token.id);
      if (user === auth_key) {
        // Auth was successful
        req.user = token.id;

        // refresh access token
        await SetAuth(redis, token.id);

        next();
      } else throw new Error("Session has expired");
    } catch (err) {
      return res.status(httpStatus.UNAUTHORIZED).json({
        status: "error",
        data: null,
        message: err.message,
        code: httpStatus.UNAUTHORIZED
      });
    }
  };
};

const SetAuth = async (redis: RedisService, user_id: string) => {
  const { JWT_SECRET, ENCRYPTION_KEY } = process.env;

  if (!JWT_SECRET) {
    throw new Error("please add JWT_SECRET to the environment variables");
  }

  if (!ENCRYPTION_KEY) {
    throw new Error("please add ENCRYPTION_KEY to the environment variables");
  }

  const jwt: JWT = new JWT(JWT_SECRET);

  const genRandomBytes = promisify(crypto.randomBytes);
  const salt = await genRandomBytes(32);
  const token = await jwt.sign({
    id: user_id,
    salt: salt.toString("hex")
  });

  // start encrption
  const aes = new AES256(Buffer.from(ENCRYPTION_KEY, "utf8"));

  //encrypt token
  const cipher = aes.encrypt(token);
  const iv = cipher.iv.toString("hex");
  const tag = cipher.tag.toString("hex");

  //combine the JWT token and the salt
  const auth_key = `${cipher.enc}.${iv}.${tag}`;

  //cache token in redis
  await redis.set(user_id, auth_key, "EX", JWT_CACHE_TTL);
  return auth_key;
};

export const SetUserAuth = SetAuth;
export const GetUserAuth = GetAuth;
