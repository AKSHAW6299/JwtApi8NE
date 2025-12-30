import express from "express";
import {
  registerUser,
  loginUser,
  refreshAccessToken,
  logoutUser,
  getUserProfile,
} from "../controllers/user.controller.js";
import { protect } from "../middleware/auth.middleware.js";



const router = express.Router();

router.post("/register", registerUser);
router.post("/login", loginUser);
router.post("/refresh-token", refreshAccessToken);
router.post("/logout", logoutUser);

// 🔐 Protected route
// protect => middleware [runs before controller]
// getUserProfile => controller
router.get("/profile", protect, getUserProfile);

export default router;
