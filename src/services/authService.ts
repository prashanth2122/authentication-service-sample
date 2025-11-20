import { PrismaClient } from "@prisma/client";
import { hashPassword, verifyPassword } from "../utils/hash";
import { signAccessToken, signRefreshToken, verifyRefreshToken } from "../utils/jwt";
import { getRedis } from "../utils/redis";
import { randomUUID } from "crypto";

const prisma = new PrismaClient();
const redis = () => getRedis();

export async function registerUser(dto: { email: string; password: string; name?: string; role?: string }) {
  const existing = await prisma.user.findUnique({ where: { email: dto.email } });
  if (existing) throw new Error("Email already in use");
  const hashed = await hashPassword(dto.password);
  const user = await prisma.user.create({
    data: { email: dto.email, password: hashed, name: dto.name, role: dto.role }
  });
  return user;
}

export async function loginUser(dto: { email: string; password: string }, ip: string, ua: string) {
  const user = await prisma.user.findUnique({ where: { email: dto.email } });
  if (!user) throw new Error("Invalid credentials");
  const ok = await verifyPassword(user.password, dto.password);
  if (!ok) throw new Error("Invalid credentials");

  const accessToken = await signAccessToken({ sub: String(user.id), role: user.role });
  const refreshToken = await signRefreshToken({ sub: String(user.id), jti: randomUUID() });

  // store session in DB and also map refresh jti in Redis for quick lookup/revocation
  const decoded = await verifyRefreshToken(refreshToken);
  const jti = decoded.jti as string;
  const sessionId = jti;

  const expiresAt = new Date();
  // compute expiry from env (simple approach)
  const refreshDays = 30;
  expiresAt.setDate(expiresAt.getDate() + refreshDays);

  await prisma.session.create({
    data: {
      id: sessionId,
      userId: user.id,
      deviceInfo: ua,
      ip,
      expiresAt,
      revoked: false
    }
  });

  // Also set in redis for fast check, store minimal info
  await redis().set(`refresh:${sessionId}`, JSON.stringify({ userId: user.id }), "EX", 60 * 60 * 24 * refreshDays);

  return { accessToken, refreshToken, accessExpiresIn: process.env.ACCESS_TOKEN_EXPIRES_IN ?? "15m" };
}

export async function rotateRefreshToken(token: string, ip: string, ua: string) {
  const payload = await verifyRefreshToken(token);
  const jti = payload.jti as string;
  if (!jti) throw new Error("Invalid token (no jti)");
  const stored = await redis().get(`refresh:${jti}`);
  if (!stored) throw new Error("Refresh token revoked or expired");

  // Revoke old session
  await prisma.session.updateMany({ where: { id: jti }, data: { revoked: true } });
  await redis().del(`refresh:${jti}`);

  // Issue new tokens
  const userId = (payload.sub as string);
  const accessToken = await signAccessToken({ sub: userId });
  const refreshToken = await signRefreshToken({ sub: userId, jti: randomUUID() });

  const newPayload = await verifyRefreshToken(refreshToken);
  const newJti = newPayload.jti as string;
  const refreshDays = 30;
  const expiresAt = new Date();
  expiresAt.setDate(expiresAt.getDate() + refreshDays);

  await prisma.session.create({
    data: {
      id: newJti,
      userId: Number(userId),
      deviceInfo: ua,
      ip,
      expiresAt,
      revoked: false
    }
  });

  await redis().set(`refresh:${newJti}`, JSON.stringify({ userId }), "EX", 60 * 60 * 24 * refreshDays);

  return { accessToken, refreshToken };
}

export async function revokeRefresh(token: string) {
  try {
    const payload = await verifyRefreshToken(token);
    const jti = payload.jti as string;
    if (!jti) return;
    await prisma.session.updateMany({ where: { id: jti }, data: { revoked: true } });
    await redis().del(`refresh:${jti}`);
  } catch {
    // ignore
  }
}
