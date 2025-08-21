// middleware/verifyAdmin.js

function verifyAdmin(req, res, next) {
  // Assuming you added role info to req.user in your auth middleware
  if (req.user && req.user.role === 'admin') {
    next();
  } else {
    return res.status(403).json({ success: false, message: 'Access denied. Admins only.' });
  }
}

module.exports = verifyAdmin;
