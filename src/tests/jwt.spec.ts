import { GetUserAuth, SetUserAuth } from "../lib/jwt";
import RedisService from "../lib/redis";
import express from "express";
import supertest from "supertest";

let redisService: RedisService;
const user_id = "12345-67890-12345-67890-12345-67890";

beforeAll(async () => {
  process.env.JWT_SECRET = "123432345432345432343";
  process.env.REDIS_URL = "redis://localhost:6379";

  redisService = new RedisService(process.env.REDIS_URL);
});

afterAll(async () => {
  redisService.quit();
});

it("should create jwt and store it in Redis", async () => {
  expect.assertions(1);

  console.time("jwt");
  const auth_key = await SetUserAuth(user_id);
  console.timeEnd("jwt");

  const redis_key = await redisService.get(user_id);
  expect(redis_key).toBe(auth_key);
});

it("should validate auth", async () => {
  expect.assertions(1);
  const app = express();
  app.get("/", GetUserAuth, (req, res, next) =>
    res.status(200).json({ message: "Hello World!" })
  );

  const res = await supertest(app)
    .get("/")
    .set("Authorization", `Bearer ${await redisService.get(user_id)}`)
    .expect(200);

  expect(res.body.message).toBe("Hello World!");
});
