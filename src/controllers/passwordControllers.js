const { pool } = require("../config/database");
const redisClient = require("../config/redis");
const crypto = require("crypto");
const sendEmail = require("../utils/sendEmail");
const logger = require("../config/logger");
const bcrypt = require("bcrypt");

const forgotPassword = async (req, res, next) => {
    try {
        const { email } = req.body;

        const userResult = await pool.query("SELECT * FROM users WHERE email = $1", [ email ]);
        if (userResult.rows.length === 0) {
            logger.warn(`Password reset requested for non-existing email: ${email}`);
            return res.status(404).json({ message: "Пользователь не найден" });
        }

        const user = userResult.rows[0];
        const resetToken = crypto.randomBytes(32).toString("hex");
        await redisClient.setex(`resetPassword:${resetToken}`, 15 * 60, user.id);
        const resetLink = `http://localhost:3000/reset-password?token=${resetToken}`;

        await sendEmail(user.email, "Восстановление пароля", `Перейдите по ссылке: ${resetLink}`);

        logger.info(`Password reset link sent to ${email}`);
        res.json({ message: "Ссылка для восстановления пароля отправлена на email"});
    } catch (error) {
        next(error);
    }
}

const resetPassword = async (req, res, next) => {
    try {
        const { token, newPassword } = req.body;
        const userId = await redisClient.get(`resetPassword: ${token}`);
        if (!userId) {
            return res.status(400).json({ message: "Недействительный или просроченный токен" });
        } 

        const hashedPassword = await bcrypt.hash(newPassword, 10);

        await pool.query("UPDATE users SET hashedPassword = $1 WHERE id = $2", [ hashedPassword, userId ]);
        await redisClient.del(`resetPassword:${token}`);
        logger.info(`User ${userId} successfully reset pasword`);
        res.json({ message: "Пароль успешно обновлен. "});
    } catch (error) {
        next(error);
    }
}

module.exports = { forgotPassword, resetPassword };