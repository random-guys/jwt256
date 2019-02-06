import crypto from "crypto";
import { NextFunction, Request, Response } from "express";
import { promisify } from "util";
import { JWT_CACHE_TTL } from "./constants";
import httpStatus from "http-status-codes";
import RedisService from "./redis";
import { AES256, JWT } from "./utils";

export const GetUserAuth = async (
  req: Request,
  res: Response,
  next: NextFunction
) => {
  try {
    const { JWT_SECRET, REDIS_URL } = process.env;

    if (!JWT_SECRET) {
      throw new Error("please add JWT_SECRET to the environment variables");
    }

    if (!REDIS_URL) {
      throw new Error("please add REDIS_URL to the environment variables");
    }

    const jwt: JWT = new JWT(JWT_SECRET);
    const redisService = new RedisService(REDIS_URL);

    const auth = req.headers.authorization;
    if (!auth) throw new Error("Session has expired");
    const auth_key = auth.split(" ")[1];

    // split the keys using the separator
    const keys = auth_key.split(".");
    const cipher = keys[0];
    const salt = keys[1];
    const tag = keys[3];
    const iv = keys[2];

    const aes = new AES256(Buffer.from(salt, "hex"));
    const plain_text = aes.decrypt(
      cipher,
      Buffer.from(iv, "hex"),
      Buffer.from(tag, "hex")
    );

    const token = await jwt.decode(plain_text);

    if ((await redisService.get(token.id)) === auth_key) next();
    else throw new Error("Session has expired");
  } catch (err) {
    return res.status(httpStatus.UNAUTHORIZED).json({
      status: "error",
      data: null,
      message: err.message,
      code: httpStatus.UNAUTHORIZED
    });
  }
};

export const SetUserAuth = async (user_id: string) => {
  const { JWT_SECRET, REDIS_URL } = process.env;

  if (!JWT_SECRET) {
    throw new Error("please add JWT_SECRET to the environment variables");
  }

  if (!REDIS_URL) {
    throw new Error("please add REDIS_URL to the environment variables");
  }

  const jwt: JWT = new JWT(JWT_SECRET);
  const redisService = new RedisService(REDIS_URL);

  const genRandomBytes = promisify(crypto.randomBytes);
  const salt = await genRandomBytes(32);
  const token = await jwt.sign({
    id: user_id,
    salt: salt.toString("hex")
  });

  // start encrption
  const aes = new AES256(Buffer.from(salt.buffer));

  //encrypt token
  const cipher = aes.encrypt(token);
  const redisKey = salt.toString("hex");
  const iv = cipher.iv.toString("hex");
  const tag = cipher.tag.toString("hex");

  //combine the JWT token and the salt
  const auth_key = `${cipher.enc}.${redisKey}.${iv}.${tag}`;

  //cache token in redis
  await redisService.set(user_id, auth_key, "EX", JWT_CACHE_TTL);
  return auth_key;
};
