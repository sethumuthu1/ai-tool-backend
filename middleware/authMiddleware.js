// middleware/authMiddleware.js
const jwt = require("jsonwebtoken");

function authMiddleware(req, res, next) {
  const authHeader = req.headers.authorization;
  if (!authHeader) return res.sendStatus(401);

  const token = authHeader.split(" ")[1];
  try {
    const user = jwt.verify(token, process.env.JWT_SECRET);
    req.user = user; // Attach decoded user info to request
    next();
  } catch (err) {
    return res.sendStatus(403);
  }
}

module.exports = authMiddleware;
