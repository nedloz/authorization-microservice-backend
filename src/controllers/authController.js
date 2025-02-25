const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const { pool } = require("../config/database");
const redis = require("../config/redis");
const logger = require("../config/logger");
const checkBruteForce = require("../middleware/rateLimiter");

const SECRET_KEY = process.env.SECRET_KEY || "your_secret_key";
const REFRESH_SECRET = process.env.REFRESH_SECRET || "your_refresh_secret";
const ACCESS_TOKEN_EXPIRE = "15m";
const REFRESH_TOKEN_EXPIRE = 60 * 60 * 24 * 7;

const generateTokens = (email) => {
  const accessToken = jwt.sign({ email }, SECRET_KEY, { expiresIn: ACCESS_TOKEN_EXPIRE })
  const refreshToken = jwt.sign({ email }, REFRESH_SECRET, { expiresIn: "7d" });
  return { accessToken, refreshToken };
}

const register = async (req, res, next) => {
  try {
    const { email, password, username } = req.body;
    const exitingUser = await pool.query("SELECT * FROM users WHERE email = $1", [ email ]);
    if (exitingUser.rows.length > 0) {
      logger.warn(`Registration failed: email ${email} is already taken`);
      return res.status(400).json({ error: "email is already taken"});
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    await pool.query("INSERT INTO users (username, email, hashedpassword) VALUES ($1, $2, $3)", [
      username, 
      email,
      hashedPassword, 
    ]);

    logger.info(`User registered: ${email} with username: ${username}`);
    res.json({ message: "User created successfully" });

  } catch (error) {
    if (error.code == "23505") {
      logger.warn(`Registration failed: email is already taken`);
      return res.status(400).json({ error: "email is already taken"});
    }
    console.error("Registration error: ", error);
    next(error);
  }
};

const login = async (req, res, next) => {
  try {
    const { email, password } = req.body;
    if (checkBruteForce(email)) {
      logger.warn(`Too many failed login attemts for user ${email}`);
      return res.status(429).json({ error: "Too many login attemts. Try again later."});
    }
    const userResult = await pool.query("SELECT * FROM users WHERE email = $1", [email]);

    if (userResult.rows.length === 0) {
      logger.warn(`Login failed: user ${email} not found`);
      return res.status(401).json({ error: "Invalid email or password"});
    }
  
    const user = userResult.rows[0];
    const isPasswordValid = await bcrypt.compare(password, user.hashedpassword);

    if (!isPasswordValid) {
      logger.warn(`Login failed: incorrect password for user ${email}`);
      return res.status(401).json({ error: "Invalid email or password"});
    }
  
    const { accessToken, refreshToken } = generateTokens(user.email);
    await redis.setex(`refresh:${user.email}`, REFRESH_TOKEN_EXPIRE, refreshToken);
    logger.info(`User logged in: ${email}`);
    res.status(200).json({ accessToken, refreshToken, token_type: "bearer" });

  } catch (error) {
    console.error("Login error: ", error);
    next(error);
  }
};

const refresh = async (req, res) => {
  try {
    const refreshToken  = req.headers.authorization?.split(" ")[1];
    if (!refreshToken) {
      return res.status(400).json({ message: "Refresh token required." });
    }
    const decoded = jwt.verify(refreshToken, REFRESH_SECRET);
    const storedToken = await redis.get(`refresh:${decoded.email}`);
    
    if (!storedToken || storedToken !== refreshToken) {
      return res.status(403).json({ message: "Invalid refresh token." });
    }
    
    const { accessToken, refreshToken: newRefreshToken } = generateTokens(decoded.email);
    await redis.setex(`refresh:${decoded.email}`, REFRESH_TOKEN_EXPIRE, newRefreshToken);

    res.json({ accessToken, refreshToken: newRefreshToken });
  } catch (error) {
    return res.status(403).json({ error: "Invalid or expired refresh token" });
  }
}

const logout = async (req, res) => {
    try {
      const userId = req.user.id;
      await redis.del(`refresh:${req.user.email}`);
      logger.info(`User logged out: ${req.user.email}`);
      res.json({ message: "Logged out successfully"});
    } catch (error) {
      next(error);
    }
}

const validateToken = async (req, res) => {
  res.json({ valid: true, email: req.user.email });
}

// спрашивать пароль при удалении аккаунта на фронте
const deleteAccount = async (req, res, next) => {
  try {
    const { email, password } = req.body;

    const userQuery = await pool.query("SELECT * FROM users WHERE email = $1", [ email ]);

    if (userQuery.rows.length === 0) {
      logger.warn(`Delete failed: user ${email} not found`);
      return res.status(404).json({ message: "User is not found"});
    }
    const user = userQuery.rows[0];

    const isPasswordValid = await bcrypt.compare(password, user.hashedpassword);
    if (!isPasswordValid) {
      logger.warn(`Delete failed: incorrect password for user ${email}`);
      return res.status(400).json({ message: "Неверный пароль"});
    }

    await pool.query("DELETE FROM users WHERE email = $1", [email]);
    await redis.del(`refresh:${user.email}`);

    logger.info(`Пользователь ${email} удалил свой аккаунт`);
    res.status(200).json({ message: "User has been successfully deleted" })
  } catch (error) {
    console.log("Delete account error: ", error);
    next(error);
  }
}



module.exports = { register, login, refresh, logout, validateToken, deleteAccount };