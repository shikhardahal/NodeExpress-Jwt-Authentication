const jwt = require('jsonwebtoken');
const User = require('../models/User');
const jwtSecret = process.env.JWT_SECRET || 'defaultSecretKey';
const requireAuth = async (req, res, next) => {
  const token = req.cookies.jwt;
  if (!token) {
    return res.redirect('/login');
  }
  try {
    const decodedToken = jwt.verify(token, jwtSecret);
    // If token is valid, proceed to the next middleware
    res.locals.user = decodedToken;
    return next();
  } catch (err) {
    if (err.name === 'TokenExpiredError') {
      // Access token expired
      const refreshToken = req.cookies.refreshToken;
      if (!refreshToken) {
        // No refresh token, redirect to login
        return res.redirect('/login');
      }
      try {
        // Verify the refresh token
        const decodedRefreshToken = jwt.verify(refreshToken, jwtSecret);
        // Create a new access token
        const newAccessToken = jwt.sign({ id: decodedRefreshToken.id }, jwtSecret, { expiresIn: '2m' });
        // Set the new access token as an HTTP-only cookie
        res.cookie('jwt', newAccessToken, { httpOnly: true, maxAge: 2 * 60 * 1000 });
        // Continue to the next middleware
        res.locals.user = decodedRefreshToken;
        return next();
      } catch (refreshErr) {
        // Refresh token is invalid
        console.error('Refresh token verification error:', refreshErr.message);
        return res.redirect('/login');
      }
    } else {
      // Other token verification errors
      console.error('Token verification error:', err.message);
      return res.redirect('/login');
    }
  }
};
const checkUser = (req, res, next) => {
  const token = req.cookies.jwt;
  if (token) {
    jwt.verify(token, jwtSecret, async (err, decodedToken) => {
      if (err) {
        console.log('Verification Error:', err.message);
        res.locals.user = null;
        next();
      } else {
        try {
          let user = await User.findById(decodedToken.id);
          res.locals.user = user;
          next();
        } catch (error) {
          console.error('Error fetching user:', error);
          res.locals.user = null;
          next();
        }
      }
    });
  } else {
    res.locals.user = null;
    next();
  }
};
module.exports = { requireAuth, checkUser };
