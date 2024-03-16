// authController.js
const User = require("../models/User");
const jwt = require('jsonwebtoken');
const maxAge = 5*60; // 
const accessTokenMaxAge = 2 * 60; // 2 minutes//
const jwtSecret = process.env.JWT_SECRET || 'defaultSecretKey';
const createTokens = (id) => {
  try {
    // Create Access Token
    const accessToken = jwt.sign({ id }, jwtSecret, { expiresIn: accessTokenMaxAge });
    // Create Refresh Token
    const refreshToken = jwt.sign({ id }, jwtSecret, { expiresIn: maxAge });
    console.log('Created Access Token:', accessToken);
    console.log('Created Refresh Token:', refreshToken);
    return { accessToken, refreshToken };
  } catch (error) {
    console.error('Token Creation Error:', error.message);
    throw error;
  }
};
module.exports.signup_get = (req, res) => {
  res.render('signup');
};
module.exports.login_get = (req, res) => {
  res.render('login');
};
module.exports.signup_post = async (req, res) => {
  const { email, password } = req.body;
  try {
    const user = await User.create({ email, password });
    const { accessToken, refreshToken } = createTokens(user._id);
    // Set Access Token as HTTP-only cookie
    res.cookie('jwt', accessToken, { httpOnly: true, maxAge: accessTokenMaxAge * 1000 });
    // Send Refresh Token to the client
    res.cookie('refreshToken', refreshToken, { httpOnly: true, maxAge: maxAge * 1000 });
    res.status(201).json({ user: user._id });
  } catch (err) {
    // ... (other error handling)
  }
};
module.exports.login_post = async (req, res) => {
  const { email, password } = req.body;
  try {
    const user = await User.login(email, password);
    if (!user) {
      res.status(401).json({ message: 'incorrect email or password' });
    } else {
      const { accessToken, refreshToken } = createTokens(user._id);
      // Set Access Token as HTTP-only cookie
      res.cookie('jwt', accessToken, { httpOnly: true, maxAge: maxAge * 1000 });
      // Send Refresh Token to the client
      res.cookie('refreshToken', refreshToken, { httpOnly: true, maxAge: maxAge * 1000 });
      // Redirect to the dashboard page
      res.redirect('/dashboard');
    }
  } catch (err) {
    console.error('Login Error:', err.message);
    res.status(500).json({ error: 'Internal Server Error' });
  }
};
module.exports.logout_get = async (req, res) => {
  try {
    // Ensure that the user information is available in req.user
    const userId = req.user ? req.user.id : null;
    const refreshToken = req.cookies.refreshToken;
    // Check if userId is not null before proceeding
    if (userId) {
      // Revoke the refresh token on the server side (if needed)
      await revokeRefreshToken(userId, refreshToken);
      // Blacklist the refresh token on the server side (optional)
      // await blacklistToken(userId);
    }
    // Clear both tokens from cookies on the client side
    res.clearCookie('jwt');
    res.clearCookie('refreshToken');
    console.log('Cookies cleared successfully');
    res.redirect('/login'); // Redirect to login page
  } catch (error) {
    console.error('Logout Error:', error);
    console.log('Error clearing cookies:', error.message);
    res.status(500).json({ error: 'Internal Server Error' });
  }
};