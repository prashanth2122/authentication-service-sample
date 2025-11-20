import argon2 from "argon2";

const time = Number(process.env.ARGON2_TIME_COST ?? 3);
const memory = Number(process.env.ARGON2_MEMORY_COST ?? 4096);
const parallelism = Number(process.env.ARGON2_PARALLELISM ?? 1);

export async function hashPassword(password: string) {
  return argon2.hash(password, { timeCost: time, memoryCost: memory, parallelism });
}

export async function verifyPassword(hash: string, password: string) {
  return argon2.verify(hash, password);
}
