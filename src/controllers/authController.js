const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const { pool } = require("../config/database");
const redis = require("../config/redis");
const logger = require("../config/logger");

const SECRET_KEY = process.env.SECRET_KEY || "your_secret_key";
const REFRESH_SECRET = process.env.REFRESH_SECRET || "your_refresh_secret";
const ACCESS_TOKEN_EXPIRE = "15m";
const REFRESH_TOKEN_EXPIRE = 60 * 60 * 24 * 7;

const generateTokens = (username, role) => {
  const accessToken = jwt.sign({ username, role }, SECRET_KEY, { expiresIn: ACCESS_TOKEN_EXPIRE })
  const refreshToken = jwt.sign({ username }, REFRESH_SECRET, { expiresIn: "7d" });
  return { accessToken, refreshToken };
}

const register = async (req, res) => {
  try {
    const { username, password, role } = req.body;
    const hashedPassword = await bcrypt.hash(password, 10);
    await pool.query("INSERT INTO users (username, hashed_password, role) VALUES ($1, $2, $3)", [username, hashedPassword, role]);
    logger.info(`User registered: ${username} with role: ${role || "user"}`);
    res.json({ message: "User created successfully" });
  } catch (error) {
    next(error);
  }
};

const login = async (req, res) => {
  try {
    const { username, password } = req.body;
    const userResult = await pool.query("SELECT * FROM users WHERE username = $1", [username]);
  
    if (userResult.rows.length === 0) {
      const error = new Error("Invalid credentials");
      error.statusCode = 401;
      throw error;
    }
  
    const user = userResult.rows[0];
    const isPasswordValid = await bcrypt.compare(password, user.hashedPassword);
    if (!isPasswordValid) {
      const error = new Error("Invalid credentials");
      error.statusCode = 401;
      throw error;
    }
  
    const { accessToken, refreshToken } = generateTokens(user.username);
    await redis.setex(`refresh:${user.username}`, REFRESH_TOKEN_EXPIRE, refreshToken);
    logger.info(`User logged in: ${username} with role: ${user.role}`);
    res.json({ accessToken, refreshToken, token_type: "bearer" });
  } catch (error) {
    next(error);
  }
};

const refresh = async (req, res) => {
  try {
    const { refreshToken } = req.body;
    if (!refreshToken) {
      const error = new Error("Refresh token required");
      error.statusCode = 401;
      throw error;
    }
    const decoded = jwt.verify(refreshToken, REFRESH_SECRET);
    const storedToken = await redis.get(`refresh:${decoded.username}`);
    
    if (!storedToken || storedToken !== refreshToken) {
      const error = new Error("Invalid refresh token");
      error.statusCode = 403;
      throw error;
    }
    
    const { accessToken, refreshToken: newRefreshToken } = generateTokens(decoded.username);
    await redis.setex(`refresh:${decoded.username}`, REFRESH_TOKEN_EXPIRE, newRefreshToken)
    res.json({ accessToken, refreshToken: newRefreshToken });
  } catch (error) {
    return res.status(403).json({ error: "Invalid or expired refresh token" });
  }
}

const logout = async (req, res) => {
    try {
      await redis.del(`refresh:${req.user.username}`);
      logger.info(`User logged out: ${username}`);
      res.json({ message: "Logged out successfully"});
    } catch (error) {
      next(error);
    }
}

const protectedRoute = async (req, res) => {
  res.json({ 
    message: `Hello, ${req.user.username}`,
    token_expires_in: ACCESS_TOKEN_EXPIRE
  });
};

module.exports = { register, login, logout, refresh, protectedRoute };