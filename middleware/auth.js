const bcrypt = require('bcryptjs');

// Middleware untuk hash password
const hashPassword = async (req, res, next) => {
  try {
    if (req.body.password) {
      const salt = await bcrypt.genSalt(10);
      req.body.hashedPassword = await bcrypt.hash(req.body.password, salt);
    }
    next();
  } catch (error) {
    console.error('Error hashing password:', error);
    res.status(500).json({
      success: false,
      message: 'Error processing password'
    });
  }
};

// Middleware untuk verifikasi password
const verifyPassword = async (plainPassword, hashedPassword) => {
  try {
    return await bcrypt.compare(plainPassword, hashedPassword);
  } catch (error) {
    console.error('Error verifying password:', error);
    return false;
  }
};

// Middleware untuk cek autentikasi admin
const requireAuth = (req, res, next) => {
  if (req.session && req.session.adminId) {
    next();
  } else {
    res.status(401).json({
      success: false,
      message: 'Unauthorized - Please login first'
    });
  }
};

module.exports = {
  hashPassword,
  verifyPassword,
  requireAuth
};