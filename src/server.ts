import express from "express";
import helmet from "helmet";
import cors from "cors";
import morgan from "morgan";
import cookieParser from "cookie-parser";
import rateLimit from "express-rate-limit";
import authRouter from "./routes/auth";
import { initRedis } from "./utils/redis";

export async function createServer() {
  const app = express();

  await initRedis();

  app.use(helmet());
  app.use(express.json({ limit: "10kb" }));
  app.use(express.urlencoded({ extended: true }));
  app.use(cookieParser());

  app.use(cors({
    origin: process.env.BASE_URL,
    credentials: true
  }));

  app.use(morgan("combined"));

  const authLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 20,
    standardHeaders: true,
    legacyHeaders: false,
    message: { success: false, error: { code: "TOO_MANY_REQUESTS", message: "Too many requests. Try later." } }
  });
  app.use("/api/v1/auth", authLimiter);

  app.use("/api/v1/auth", authRouter);

  app.get("/health", (_, res) => res.json({ status: "ok" }));

  return app;
}
