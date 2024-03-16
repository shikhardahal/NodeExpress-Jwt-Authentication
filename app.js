// app.js
const express = require('express');
const mongoose = require('mongoose');
const authRoutes = require('./routes/authRoutes');
const app = express();
require('dotenv').config();
const PORT = process.env.PORT || 4000;
const cookieParser = require('cookie-parser');
// Import middleware functions
const { requireAuth, checkUser } = require('./middleware/authMiddleware');
// middleware
app.use(express.static('public'));
app.use(express.json());
app.use(cookieParser());
// view engine
app.set('view engine', 'ejs');
// MongoDB Connection
const MONGODB_URL = process.env.MONGODB_URL;
mongoose.connect(MONGODB_URL, {
  useNewUrlParser: true,
  useUnifiedTopology: true,
})
  .then(() => console.log('MongoDB connected'))
  .catch((err) => console.error('MongoDB connection error:', err));
// routes
app.use(authRoutes);
// Middleware to check the user for every route
app.get('/login', (req, res) => res.render('login.ejs'));
app.get('/signup', (req, res) => res.render('signup.ejs'));
app.get('/dashboard', requireAuth, (req, res) => res.render('dashboard.ejs'));
app.post('/logout', (req, res) => {
  res.cookie('jwt', '', { maxAge: 1, httpOnly: true });
  res.status(200).json({ message: 'Logout successful' });
});
// This wildcard route should be at the end
app.get('*', checkUser, (req, res) => {
  // Handle unmatched routes or render a 404 page
  res.status(404).send('404 Not Found');
});
app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});
