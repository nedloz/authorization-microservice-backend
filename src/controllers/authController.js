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

const generateTokens = (username) => {
  const accessToken = jwt.sign({ username }, SECRET_KEY, { expiresIn: ACCESS_TOKEN_EXPIRE })
  const refreshToken = jwt.sign({ username }, REFRESH_SECRET, { expiresIn: "7d" });
  return { accessToken, refreshToken };
}

const register = async (req, res, next) => {
  try {
    const { username, password, nickname } = req.body;

    const exitingUser = await pool.query("SELECT * FROM users WHERE username = $1", [ username ]);
    if (exitingUser.rows.length > 0) {
      logger.warn(`Registration failed: username ${username} is already taken`);
      return res.status(400).json({ error: "Username is already taken"});
    }

    const exitingNickname = await pool.query("SELECT * FROM users WHERE nickname =1$", [ nickname ]);
    if (exitingNickname.rows.length > 0) {
      logger.warn(`Registration failed:  nickname ${username} is already taken`);
      return res.status(400).json({ error: "Nickname is already taken"});
    }
    

    const hashedPassword = await bcrypt.hash(password, 10);
    await pool.query("INSERT INTO users (username, hashed_password) VALUES ($1, $2, $3)", [
      username, 
      hashedPassword,
      nickname, 
    ]);

    logger.info(`User registered: ${username} with nickname: ${nickname}`);
    res.json({ message: "User created successfully" });

  } catch (error) {
    console.error("Registration error: ", error);
    next(error);
  }
};

const login = async (req, res, next) => {
  try {
    const { username, password } = req.body;

    if (checkBruteForce(username)) {
      logger.warn(`Too many failed login attemts for user ${username}`);
      return res.status(429).json({ error: "Too many login attemts. Try again later."});
    }
    const userResult = await pool.query("SELECT * FROM users WHERE username = $1", [username]);
  
    if (userResult.rows.length === 0) {
      logger.warn(`Login failed: user ${username} not found`);
      return res.status(401).json({ error: "Invalid username or password"});
    }
  
    const user = userResult.rows[0];
    const isPasswordValid = await bcrypt.compare(password, user.hashedPassword);
    if (!isPasswordValid) {
      logger.warn(`Login failed: incorrect password for user ${username}`);
      return res.status(401).json({ error: "Invalid username or password"});
    }
  
    const { accessToken, refreshToken } = generateTokens(user.username);
    await redis.setex(`refresh:${user.username}`, REFRESH_TOKEN_EXPIRE, refreshToken);

    logger.info(`User logged in: ${username}`);
    res.json({ accessToken, refreshToken, token_type: "bearer" });

  } catch (error) {
    console.error("Login error: ", error);
    next(error);
  }
};

const refresh = async (req, res) => {
  try {
    const { refreshToken } = req.body;
    if (!refreshToken) {
      return res.status(401).json({ message: "Refresh token required." });
    }
    const decoded = jwt.verify(refreshToken, REFRESH_SECRET);
    const storedToken = await redis.get(`refresh:${decoded.username}`);
    
    if (!storedToken || storedToken !== refreshToken) {
      return res.status(403).json({ message: "Invalid refresh token." });
    }
    
    const { accessToken, refreshToken: newRefreshToken } = generateTokens(decoded.username);
    await redis.setex(`refresh:${decoded.username}`, REFRESH_TOKEN_EXPIRE, newRefreshToken);

    res.json({ accessToken, refreshToken: newRefreshToken });
  } catch (error) {
    return res.status(403).json({ error: "Invalid or expired refresh token" });
  }
}

const logout = async (req, res) => {
    try {
      const userId = req.user.id;
      await redis.del(`refresh:${req.user.username}`);
      logger.info(`User logged out: ${req.user.username}`);
      res.json({ message: "Logged out successfully"});
    } catch (error) {
      next(error);
    }
}

const validateToken = async (req, res) => {
  res.json({ valid: true, username: req.user.username });
}

// спрашивать пароль при удалении аккаунта на фронте
const deleteAccount = async (req, res, next) => {
  try {
    const userId = req.user.id;
    const { password } = req.body;

    const userQuery = await pool.query("SELECT * FROM users WHERE id = $1", [ userId ]);
    if (userQuery.rows.length === 0) {
      return res.status(404).json({ message: "User is not found"});
    }
    const user = userQuery.rows[0];

    const isMatch = await bcrypt.compare(password, user.password);
    if (isMatch) {
      return res.status(400).json({ message: "Неверный пароль"});
    }

    await pool.query("DELETE FROM users WHERE id = $1", [userId]);

    await redisClient.del(`refreshToken:${userId}`);

    logger.info(`Пользователь ${userId} удалил свой аккаунт`);
    
    res.status(200).json({ message: "User has been successfully deleted" })
  } catch (error) {
    console.error("Delete account error: ", error);
    next(error);
  }
}



module.exports = { register, login, logout, refresh, validateToken, deleteAccount };