import User from "../models/user.model.js";
import jwt from "jsonwebtoken";

/* =========================
   ✅ REGISTER + AUTO LOGIN
========================= */
export const registerUser = async (req, res) => {
  try {
    const { name, email, password } = req.body;
    // 1️) Validate input
    if (!name || !email || !password) {
      return res.status(400).json({
        success: false,
        message: "All fields are required",
      });
    }

    // 2️) Check if user already exists
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(409).json({
        success: false,
        message: "User already exists",
      });
    }

    // 3️) Create user
    const user = await User.create({ name, email, password });

    // 4️) Generate tokens (AUTO LOGIN)
    const { accessToken, refreshToken } = user.generateToken();

    // 5️) Save refresh token in DB
    user.refreshToken = refreshToken;
    await user.save();

    // Store refresh token in HTTP-only cookie [server]
    // Nobody can access this cookies from frontend
    res.cookie("refreshToken", refreshToken, {
      httpOnly: true,                                    // only server can access, js cannot access
      secure: process.env.NODE_ENV === "production",
      sameSite: "none",                                 // cross-domain allowed
      maxAge: 24 * 60 * 60 * 1000, // 1 day
    });

    res.status(201).json({
      success: true,
      message: "User registered & logged in successfully",
      accessToken,
      // refreshToken,  // $$) Never send refresh token here in response!
      user: {
        id: user._id,
        name: user.name,
        email: user.email,
      },
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      message: error.message,
    });
  }
};

/* =========================
   ✅ LOGIN USER
========================= */
export const loginUser = async (req, res) => {
  try {
    const { email, password } = req.body;

    // 1️) Validate
    if (!email || !password) {
      return res.status(400).json({
        success: false,
        message: "Email and password are required",
      });
    }

    // 2️) Find user (explicitly select password)
    const user = await User.findOne({ email }).select("+password");
    if (!user) {
      return res.status(401).json({
        success: false,
        message: "Invalid credentials",
      });
    }

    // 3️) Compare password
    const isMatch = await user.comparePassword(password);
    if (!isMatch) {
      return res.status(401).json({
        success: false,
        message: "Invalid credentials",
      });
    }

    // 4️) Generate tokens
    const { accessToken, refreshToken } = user.generateToken();

    // 5️) Save refresh token
    user.refreshToken = refreshToken;
    await user.save();

    // 6) Store refresh token in HTTP-only cookie
    res.cookie("refreshToken", refreshToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      sameSite: "none",
      maxAge: 24 * 60 * 60 * 1000,
    });

    res.status(200).json({
      success: true,
      message: "Login successful",
      accessToken,
      // refreshToken,   // $$) Never send refresh token here in response!
      user: {
        id: user._id,
        name: user.name,
        email: user.email,
      },
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      message: error.message,
    });
  }
};

/* =========================
   🔁 REFRESH ACCESS TOKEN
========================= */
export const refreshAccessToken = async (req, res) => {
  try {
    // Read refresh token from HTTP-only cookie
    const  refreshToken  = req.cookies.refreshToken

    if (!refreshToken) {
      return res.status(401).json({
        success: false,
        message: "No refresh token found, please login again",
      });
    }

    // 1️) Verify refresh token
    const decoded = jwt.verify(
      refreshToken,
      process.env.REFRESH_TOKEN_SECRET
    );

    // 2️) Find user
    const user = await User.findById(decoded._id);
    if (!user || user.refreshToken !== refreshToken) {
      return res.status(403).json({
        success: false,
        message: "Invalid refresh token",
      });
    }

    // 3️) Generate new access token
    const accessToken = jwt.sign(
      { _id: user._id },
      process.env.ACCESS_TOKEN_SECRET,
      { expiresIn: "15m" }
    );

    res.status(200).json({
      success: true,
      message: "Access token refreshed successfully",
      accessToken,
    });
  } catch (error) {
    res.status(403).json({
      success: false,
      message: "Invalid or expired refresh token",
    });
  }
};

/* =========================
   🚪 LOGOUT USER
========================= */
export const logoutUser = async (req, res) => {
  try {
    // #) Get refresh token from HTTP-only cookie
    const refreshToken = req.cookies.refreshToken;

    if (refreshToken) {
      // 1️) Find user with this refresh token
      const user = await User.findOne({ refreshToken });

      // 2️) Invalidate refresh token in DB
      if (user) {
        user.refreshToken = "";
        await user.save();
      }
    }

    // 3️) Clear refresh token cookie
    res.clearCookie("refreshToken", {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      sameSite: "none",
    });

    res.status(200).json({
      success: true,
      message: "Logout successful",
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      message: error.message,
    });
  }
};


export const getUserProfile = async (req, res) => {
  try {
    // req.user comes from protect middleware
    res.status(200).json({
      success: true,
      user: req.user,
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      message: error.message,
    });
  }
};
