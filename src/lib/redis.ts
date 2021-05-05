import redis, { RedisClient } from "redis";
import { promisify } from "util";

export default class RedisService {
  redis: RedisClient;

  del: (key: string) => Promise<number>;
  expire: (key: string, seconds: number) => Promise<number>;
  expireat: (key: string, timestamp: number) => Promise<number>;
  incrby: (key: string, increment: number) => Promise<number>;
  hdel: (hash: string, field: string) => Promise<any>;
  hget: (hash: string, field: string) => Promise<string>;
  hgetall: (key: string) => Promise<object>;
  hset: (hash: string, field: string, value: any) => Promise<any>;
  set: (
    key: string,
    value: any,
    mode?: string,
    duration?: number
  ) => Promise<any>;
  get: (key: string) => Promise<string>;
  quit: () => Promise<void>;
  flushall: (async: "ASYNC") => Promise<string>;

  constructor(url: string) {
    this.redis = redis.createClient({ url });

    const commands = [
      "del",
      "expire",
      "expireat",
      "incrby",
      "hdel",
      "hget",
      "hgetall",
      "flushall",
      "hset",
      "set",
      "get",
      "quit",
    ];

    // Promisify all the specified commands
    commands.forEach((command) => {
      this[command] = promisify(this.redis[command]).bind(this.redis);
    });
  }
}
