import { GetUserAuth, SetUserAuth, GetUserToken } from '../lib/jwt';
import RedisService from '../lib/redis';
import express from 'express';
import supertest from 'supertest';

let redisService: RedisService;
const user_id = '1a16acbd-ae44-444c-9271-4bc5504b127c';
let redis_key = '';

beforeAll(async () => {
  process.env.JWT_SECRET = '123432345432345432343';
  process.env.REDIS_URL = 'redis://localhost:6379';
  process.env.ENCRYPTION_KEY = '4844e2650b69fd92f0af204275ca74b9';

  redisService = new RedisService(process.env.REDIS_URL);
});

afterAll(async () => {
  redisService.quit();
});

it('should create jwt and store it in Redis', async () => {
  expect.assertions(1);

  console.time('jwt');
  const auth_key = await SetUserAuth(redisService, user_id);
  console.timeEnd('jwt');

  redis_key = await redisService.get(user_id);
  expect(redis_key).toBe(auth_key);
});

it('should validate auth', async () => {
  expect.assertions(4);
  const app = express();

  console.time('jwt');
  app.get('/', GetUserAuth(redisService), (req, res, next) => {
    expect(req.user).toBe(user_id);
    console.timeEnd('jwt');
    res.status(200).json({ message: 'Hello World!' });
  });

  app.get('/hi', GetUserAuth(redisService), (req, res, next) => {
    expect(req.user).toBe(user_id);
    console.timeEnd('jwt');
    res.status(200).json({ message: 'Hi World!' });
  });

  const res = await supertest(app)
    .get('/')
    .set('Authorization', `Bearer ${redis_key}`)
    .expect(200);

  const anotherRes = await supertest(app)
    .get('/hi')
    .set('Authorization', `Bearer ${redis_key}`)
    .expect(200);

  expect(res.body.message).toBe('Hello World!');
  expect(anotherRes.body.message).toBe('Hi World!');
});

it("should get the user's raw token", async () => {
  expect.assertions(1);
  const app = express();

  app.get('/', async (req, res, next) => {
    const token = await GetUserToken(req);
    expect(token).toBe(user_id);
    res.status(200).json({ message: 'Hello World!' });
  });

  const res = await supertest(app)
    .get('/')
    .set('Authorization', `Bearer ${redis_key}`)
    .expect(200);
});

it("should get the user's raw token and fail", async () => {
  expect.assertions(1);
  const app = express();

  app.get('/', (req, res, next) => {
    expect(GetUserToken(req)).rejects.toBe('Missing Auth Header');
    res.status(400).json({ error: 'Missing Auth Header' });
  });

  const res = await supertest(app)
    .get('/')
    .expect(400);
});
