import express from "express";
import { register, login, refresh, logout, getProfile } from "../controllers/authController";
import { requireAuth } from "../middleware/authMiddleware";

const router = express.Router();

router.post("/register", register);
router.post("/login", login);
router.post("/refresh", refresh);
router.post("/logout", logout);
router.get("/profile", requireAuth, getProfile);

export default router;
