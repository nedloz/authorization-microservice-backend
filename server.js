const express = require("express");
const dotenv = require("dotenv");
const cors = require("cors");
const { connectDB } = require("./config/database");
const authRoutes = require("./routes/authRoutes");

dotenv.config();

const app = express();
app.use(express.json());

app.use(cors({
    origin: "http://localhost:3001",
    methods: ["GET","POST","PUT","DELETE"],
    allowedHeaders: ["Content-Type", "Authorization"]
}));

// Используем маршруты
app.use("/auth", authRoutes);

const PORT = process.env.PORT || 3000;
app.listen(PORT, async () => {
  await connectDB();
  console.log(`Auth service running on port ${PORT}`);
});



