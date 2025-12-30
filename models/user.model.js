import mongoose from "mongoose";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";

const userSchema = new mongoose.Schema(
  {
    name: {
      type: String,
      trim: true,
    },
    email: {
      type: String,
      lowercase: true,
      trim: true,
    },
    password: {
      type: String,
      select: false, // hide password in queries by default
    },
    refreshToken: {
      type: String,
      default: "",
    },
  },
  {
    timestamps: true,
  }
);

/* =========================
   🔐 Hash password before save
========================= */
userSchema.pre("save", async function (next) {
  if (!this.isModified("password")) return next();

  const salt = await bcrypt.genSalt(10);
  this.password = await bcrypt.hash(this.password, salt);
  next();
});

/* =========================
   🔑 Compare password
========================= */
userSchema.methods.comparePassword = async function (enteredPassword) {
  return await bcrypt.compare(enteredPassword, this.password);
};

/* =========================
   🔐 Generate JWT tokens
========================= */
userSchema.methods.generateToken = function () {
  const accessToken = jwt.sign(
    { _id: this._id },
    process.env.ACCESS_TOKEN_SECRET,
    { expiresIn: "15m" }
  );
  const refreshToken = jwt.sign(
    { _id: this._id },
    process.env.REFRESH_TOKEN_SECRET,
    { expiresIn: "1d" }
  );
  return { accessToken, refreshToken };
};

const User = mongoose.model("User", userSchema);
export default User;