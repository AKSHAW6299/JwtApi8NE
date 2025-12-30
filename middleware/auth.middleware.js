import jwt from "jsonwebtoken";
import User from "../models/user.model.js";

export const protect = async (req, res, next) => {
  try {
    let token;

    // 1) Read token from Authorization header
    if (
      req.headers.authorization &&
      req.headers.authorization.startsWith("Bearer")
    ) {
      token = req.headers.authorization.split(" ")[1];    // Access token
    }

    if (!token) {
      return res.status(401).json({
        success: false,
        message: "Not authorized, token missing",
      });
    }

    // 2) Verify access token
    const decoded = jwt.verify(token, process.env.ACCESS_TOKEN_SECRET);

    // 3 Attach user to request
    req.user = await User.findById(decoded._id).select("-password");

    if (!req.user) {
      return res.status(401).json({
        success: false,
        message: "User not found",
      });
    }

    next();
  } catch (error) {
    return res.status(401).json({
      success: false,
      message: "Not authorized, token invalid or expired",
    });
  }
};
