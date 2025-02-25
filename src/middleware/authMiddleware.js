const jwt = require("jsonwebtoken");
const redis = require("../config/redis");
const SECRET_KEY = process.env.SECRET_KEY || "your_secret_key";
const REFRESH_SECRET = process.env.REFRESH_SECRET || "your_refresh_secret";

const authMiddleware = async (req, res, next) => {
  try {
    const authHeader = req.headers.authorization || req.headers["authorization"];
    if (!authHeader || !authHeader.startsWith("Bearer ")) {
      return res.status(401).json({ error: "Access token required" });
    }

    const token = authHeader.split(" ")[1];
    const payload = jwt.verify(token, REFRESH_SECRET); 
    const storedToken = await redis.get(`refresh:${payload.email}`);

    if (!storedToken || storedToken !== token) {
      return res.status(401).json({ error: "Invalid or expired access token" });
    }
    req.user = payload;
    next();
  } catch (error) {
    console.log("AuthMiddleware account error: ", error);
    res.status(401).json({ error: "Invalid or expired token" });
  }
};

module.exports = { authMiddleware };