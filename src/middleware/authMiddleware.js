const jwt = require("jsonwebtoken");
const redis = require("../config/redis");
const SECRET_KEY = process.env.SECRET_KEY || "your_secret_key";

const authMiddleware = async (req, res, next) => {
  const token = req.headers.authorization?.split(" ")[1];
  if (!token) {
    return res.status(401).json({ error: "Token required" });
  }

  try {
    const payload = jwt.verify(token, SECRET_KEY);
    const storedToken = await redis.get(payload.username);
    if (!storedToken) {
      return res.status(401).json({ error: "Token expired" });
    }
    req.user = payload;
    next();
  } catch (error) {
    res.status(401).json({ error: "Invalid or expired token" });
  }
};

module.exports = { authMiddleware };