import { Request, Response } from "express";
import { z } from "zod";
import { registerUser, loginUser, rotateRefreshToken, revokeRefresh } from "../services/authService";

const registerSchema = z.object({
  name: z.string().min(1).optional(),
  email: z.string().email(),
  password: z.string().min(8),
  role: z.enum(["user", "admin"]).optional()
});

const loginSchema = z.object({
  email: z.string().email(),
  password: z.string().min(8)
});

export async function register(req: Request, res: Response) {
  try {
    const dto = registerSchema.parse(req.body);
    const user = await registerUser(dto);
    res.status(201).json({ success: true, data: { id: user.id, email: user.email,role:user.role } });
  } catch (err: any) {
    res.status(400).json({ success: false, error: { code: "INVALID_INPUT", message: err.message } });
  }
}

export async function login(req: Request, res: Response) {
  try {
    const dto = loginSchema.parse(req.body);
    const ip = req.ip ?? "unknown";
    const ua = req.get("User-Agent") ?? "unknown";
    const tokens = await loginUser(dto, ip, ua);
    res
      .cookie("refreshToken", tokens.refreshToken, {
        httpOnly: true,
        secure: process.env.NODE_ENV === "production",
        sameSite: "lax",
        maxAge: 1000 * 60 * 60 * 24 * 30 // 30d
      })
      .json({ success: true, data: { accessToken: tokens.accessToken } });
  } catch (err: any) {
    res.status(401).json({ success: false, error: { code: "AUTH_FAILED", message: err.message } });
  }
}
export async function refresh(req: Request, res: Response) {
  try {
    // refresh can use cookie or body
    const token = req.cookies?.refreshToken || req.body?.refreshToken;
    if (!token) throw new Error("No refresh token");
    const ip = req.ip ?? "unknown";
    const ua = req.get("User-Agent") ?? "unknown";
    const tokens = await rotateRefreshToken(token, ip, ua);
    res
      .cookie("refreshToken", tokens.refreshToken, {
        httpOnly: true,
        secure: process.env.NODE_ENV === "production",
        sameSite: "lax",
        maxAge: 1000 * 60 * 60 * 24 * 30
      })
      .json({ success: true, data: { accessToken: tokens.accessToken } });
  } catch (err: any) {
    res.status(401).json({ success: false, error: { code: "INVALID_REFRESH", message: err.message } });
  }
}
  


export async function logout(req: Request, res: Response) {
  try {
    const token = req.cookies?.refreshToken || req.body?.refreshToken;
    if (token) await revokeRefresh(token);
    res.clearCookie("refreshToken").json({ success: true });
  } catch (err: any) {
    res.status(400).json({ success: false, error: { code: "LOGOUT_FAILED", message: err.message } });
  }
}

export async function getProfile(req: Request, res: Response) {
  // requireAuth will set req.userId
  res.json({ success: true, data: { userId: (req as any).userId } });
}
