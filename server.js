const express = require("express");
const dotenv = require("dotenv");
const cors = require("cors");
const { connectDB } = require("./config/database");
const authRoutes = require("./routes/authRoutes");
const errorHandler = require("./middleware/errorHandler");
const logger = require("./config/logger");

dotenv.config();

const app = express();
app.use(express.json());

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
app.listen(PORT, async () => {
  await connectDB();
  logger.info(`Auth service running on port ${PORT}`);
});



