import Redis from "ioredis";

let redis: Redis | null = null;

export async function initRedis() {
  if (!redis) {
    redis = new Redis(process.env.REDIS_URL);
    redis.on("error", (e) => console.error("Redis error", e));
    await redis.ping();
  }
  return redis;
}

export function getRedis() {
  if (!redis) throw new Error("Redis not initialized");
  return redis;
}
