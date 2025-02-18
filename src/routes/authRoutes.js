const express = require("express");
const { register, login, logout, refresh, validateToken } = require("../controllers/authController");
const { authMiddleware } = require("../middleware/authMiddleware");

const router = express.Router();

router.post("/register", register);
router.post("/login", login);
router.post("/logout", authMiddleware, logout);
router.get("/refresh", authMiddleware, refresh);
router.get("/validate", authMiddleware, validateToken);

module.exports = router;