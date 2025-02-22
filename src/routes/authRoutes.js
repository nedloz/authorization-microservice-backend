const express = require("express");
const { register, login, logout, refresh, validateToken, deleteAccount } = require("../controllers/authController");
const { authMiddleware } = require("../middleware/authMiddleware");
const {forgotPassword, resetPassword} = require("../controllers/passwordControllers");

const router = express.Router();

router.post("/register", register);
router.post("/login", login);
router.post("/logout", authMiddleware, logout);
router.get("/refresh", authMiddleware, refresh);
router.get("/validate", authMiddleware, validateToken);
router.delete("/delete-account", authMiddleware, deleteAccount);
router.post("/forgot-password", forgotPassword);
router.post("/reset-password", resetPassword);

module.exports = router;