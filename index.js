const jwt = require("jsonwebtoken");

class AppError extends Error {
  constructor(statusCode, message) {
    super(message);
    this.statusCode = statusCode;
  }
}


const verifyToken = (publicKey) => (req, res, next) => {
  const header = req.headers.authorization;
  const token = header?.startsWith("Bearer ")
    ? header.split(" ")[1]
    : req.cookies?.token; 

  if (!token) return next(new AppError(401, "Token missing"));

  try {
    const decoded = jwt.verify(token, publicKey, { algorithms: ["RS256"] });
    req.user = { userId: decoded.userId, role: decoded.role };
    next();
  } catch (err) {
    next(new AppError(401, "Invalid or expired token"));
  }
};


const checkRole = (...allowed) => (req, res, next) => {
  if (!req.user) return next(new AppError(401, "Not authenticated"));
  if (!allowed.includes(req.user.role))
    return next(new AppError(403, "Access denied"));
  next();
};


const errorHandler = (err, req, res, next) => {
  const status = err.statusCode || 500;
  res.status(status).json({
    message: status === 500 ? "Internal server error" : err.message,
  });
};

module.exports = { verifyToken, checkRole, errorHandler, AppError };