const errorHandler = (err, req, res, next) => {
    logger.error(`${err.message} - ${req.method} ${req.url}`);
    const statusCode = err.statusCode || 500;
    res.status(statusCode).json({
        error: err.message || "Internal Server Error"
    });
}

module.exports = errorHandler;