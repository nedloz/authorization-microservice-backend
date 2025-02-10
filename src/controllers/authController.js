const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const { pool } = require("../config/database");
const redis = require("../config/redis");

const SECRET_KEY = process.env.SECRET_KEY || "your_secret_key";
const ACCESS_TOKEN_EXPIRE = "30m";

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
  const isPasswordValid = await bcrypt.compare(password, user.hashed_password);
  if (!isPasswordValid) {
    return res.status(401).json({ error: "Invalid credentials" });
  }

  const accessToken = jwt.sign({ username: user.username }, SECRET_KEY, { expiresIn: ACCESS_TOKEN_EXPIRE });
  await redis.setex(user.username, 1800, accessToken);

  res.json({ accessToken, token_type: "bearer" });
};

const logout = async (req, res) => {
    try {
        await redis.del(req.user.username);
        res.json({ message: "Logged out successfully"});
    } catch (error) {
        res.status(500).json({ error: "Logout failed"});
    }
}

const protectedRoute = async (req, res) => {
  res.json({ message: `Hello, ${req.user.username}` });
};

module.exports = { register, login, logout, protectedRoute };