
import { readFileSync } from "fs";
import { SignJWT, jwtVerify, importPKCS8, importSPKI, JWTPayload } from "jose";

function requireEnv(name: string): string {
  const value = process.env[name];
  if (!value) {
    throw new Error(`Environment variable '${name}' is required but not set.`);
  }
  return value;
}

const accessPrivate = readFileSync(requireEnv("JWT_ACCESS_PRIVATE_KEY_PATH"), "utf8");
const accessPublic = readFileSync(requireEnv("JWT_ACCESS_PUBLIC_KEY_PATH"), "utf8");
const refreshPrivate = readFileSync(requireEnv("JWT_REFRESH_PRIVATE_KEY_PATH"), "utf8");
const refreshPublic = readFileSync(requireEnv("JWT_REFRESH_PUBLIC_KEY_PATH"), "utf8");

const ACCESS_EXP = process.env.ACCESS_TOKEN_EXPIRES_IN ?? "15m";
const REFRESH_EXP = process.env.REFRESH_TOKEN_EXPIRES_IN ?? "30d";

export type TokenPair = { accessToken: string; refreshToken: string; accessExpiresIn: string };

export async function signAccessToken(payload: JWTPayload) {
  const privateKey = await importPKCS8(accessPrivate, "RS256");
  const token = await new SignJWT(payload)
    .setProtectedHeader({ alg: "RS256", typ: "JWT" })
    .setIssuedAt()
    .setExpirationTime(ACCESS_EXP)
    .sign(privateKey);
  return token;
}

export async function signRefreshToken(payload: JWTPayload) {
  const privateKey = await importPKCS8(refreshPrivate, "RS256");
  const token = await new SignJWT(payload)
    .setProtectedHeader({ alg: "RS256", typ: "JWT" })
    .setIssuedAt()
    .setExpirationTime(REFRESH_EXP)
    .sign(privateKey);
  return token;
}

export async function verifyAccessToken(token: string) {
  const pub = await importSPKI(accessPublic, "RS256");
  const { payload } = await jwtVerify(token, pub);
  return payload as JWTPayload;
}

export async function verifyRefreshToken(token: string) {
  const pub = await importSPKI(refreshPublic, "RS256");
  const { payload } = await jwtVerify(token, pub);
  return payload as JWTPayload;
}
