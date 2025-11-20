import { Request, Response, NextFunction } from "express";
import { verifyAccessToken } from "../utils/jwt";

export async function requireAuth(req: Request, res: Response, next: NextFunction) {
  try {
    const header = req.get("Authorization");
    if (!header || !header.startsWith("Bearer ")) return res.status(401).json({ success: false, error: { code: "NO_TOKEN", message: "No bearer token" } });
    const token = header.slice(7);
    const payload = await verifyAccessToken(token);
    (req as any).userId = payload.sub;
    next();
  } catch (err: any) {
    res.status(401).json({ success: false, error: { code: "INVALID_TOKEN", message: "Token invalid or expired" } });
  }
}
