const express = require("express");
const dotenv = require("dotenv");
const cors = require("cors");
const rateLimit = require("express-rate-limit");
const helmet = require("helmet");
const { connectDB } = require("./config/database");
const authRoutes = require("./routes/authRoutes");
const errorHandler = require("./middleware/errorHandler");
const logger = require("./config/logger");

dotenv.config();

const app = express();
app.use(express.json());
app.use(helmet());

const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
  message: "Too many requests from this IP, please try again later"
})
app.use(limiter);

app.use(cors({
    origin: "http://localhost:3001",
    methods: ["GET","POST","PUT","DELETE"],
    allowedHeaders: ["Content-Type", "Authorization"]
}));

app.use((req, res, next) => {
  logger.info(`${req.method} ${req.url}`);
  next();
})

// Используем маршруты
app.use("/auth", authRoutes);

app.use(errorHandler);

const PORT = process.env.PORT || 3000;
let server = null;
if (process.env.NODE_ENV !== "test") {
  server = app.listen(PORT, async () => {
    await connectDB();
    logger.info(`Auth service running on port ${PORT}`);
  });
}


module.exports = { app, server };
