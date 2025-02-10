const express = require("express");
const { register, login, protectedRoute, logout} = require("./controllers/authcontroller");
const { authMiddleware } = require("./middleware/authMiddleware");

const router = express.Router();

router.post("/register", register);
router.post("/login", login);
router.post("/logout", authMiddleware, logout);
router.get("/protected", authMiddleware, protectedRoute);

module.exports = router;