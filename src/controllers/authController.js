const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const { pool } = require("../config/database");
const redis = require("../config/redis");

const SECRET_KEY = process.env.SECRET_KEY || "your_secret_key";
const REFRESH_SECRET = process.env.REFRESH_SECRET || "your_refresh_secret";
const ACCESS_TOKEN_EXPIRE = "15m";
const REFRESH_TOKEN_EXPIRE = 60 * 60 * 24 * 7;

const generateTokens = (username) => {
  const accessToken = jwt.sign({ username }, SECRET_KEY, { expiresIn: ACCESS_TOKEN_EXPIRE })
  const refreshToken = jwt.sign({ username }, REFRESH_SECRET, { expiresIn: "7d" });

  return { accessToken, refreshToken };
}

const register = async (req, res) => {
  const { username, password } = req.body;
  const hashedPassword = await bcrypt.hash(password, 10);

  try {
    await pool.query("INSERT INTO users (username, hashed_password) VALUES ($1, $2)", [username, hashedPassword]);
    res.json({ message: "User created successfully" });
  } catch (error) {
    res.status(400).json({ error: "User already exists" });
  }
};

const login = async (req, res) => {
  const { username, password } = req.body;
  const userResult = await pool.query("SELECT * FROM users WHERE username = $1", [username]);

  if (userResult.rows.length === 0) {
    return res.status(401).json({ error: "Invalid credentials" });
  }

  const user = userResult.rows[0];
  const isPasswordValid = await bcrypt.compare(password, user.hashedPassword);
  if (!isPasswordValid) {
    return res.status(401).json({ error: "Invalid credentials" });
  }

  const { accessToken, refreshToken } = generateTokens(user.username);

  await redis.setex(`refresh:${user.username}`, REFRESH_TOKEN_EXPIRE, refreshToken);

  res.json({ accessToken, refreshToken, token_type: "bearer" });
};

const refresh = async (req, res) => {
  const { refreshToken } = req.body;
  if (!refreshToken) {
    return res.status(401).json({ error: "Refresh token required" });
  }

  try {
    const decoded = jwt.verify(refreshToken, REFRESH_SECRET);
    const storedToken = await redis.get(`refresh:${decoded.username}`);
    
    if (!storedToken || storedToken !== refreshToken) {
      return res.status(403).json({ error: "Invalid refresh token" });
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
        res.json({ message: "Logged out successfully"});
    } catch (error) {
        res.status(500).json({ error: "Logout failed"});
    }
}

const protectedRoute = async (req, res) => {
  res.json({ 
    message: `Hello, ${req.user.username}`,
    token_expires_in: ACCESS_TOKEN_EXPIRE
  });
};

module.exports = { register, login, logout, refresh, protectedRoute };