const express = require('express');
const router = new express.Router();
const ExpressError = require('../expressError');
const User = require('../models/user');
const Message = require('../models/message');
const db = require('../db');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const {
  ensureLoggedIn,
  ensureCorrectUser,
  authenticateJWT,
} = require('../middleware/auth');
const { SECRET_KEY, BCRYPT_WORK_FACTOR } = require('../config');

/** POST /login - login: {username, password} => {token}
 *
 * Make sure to update their last-login!
 *
 **/

router.post('/login', async (req, res, next) => {
  try {
    const { username, password } = req.body;
    if (!username || !password) {
      throw new ExpressError('Must have Username and Password', 400);
    }
    const auth = await User.authenticate(username, password);
    if (auth) {
      const token = jwt.sign({ username: username }, SECRET_KEY);
      await User.updateLoginTimestamp(username);
      return res.json({ message: `Logged in as ${username}`, token: token });
    }
    throw new ExpressError('Invalid username/password', 400);
  } catch (e) {
    return next(e);
  }
});

router.post('/register', async (req, res, next) => {
  try {
    const { username, password, first_name, last_name, phone } = req.body;
    if (!username || !password || !first_name || !last_name || !phone) {
      throw new ExpressError(
        'Incomplete Registration - Must have username, password, first_name, last_name, and phone in Request Body',
        400
      );
    }
    const user = await User.register(req.body);
    if (user) {
      const token = jwt.sign({ username: username }, SECRET_KEY);
      await User.updateLoginTimestamp(user.username);
      return res.json({
        message: `Successfully Registered User ${username}`,
        token: token,
      });
    }
  } catch (e) {
    if (e.code === '23505') {
      return next(new ExpressError('Please Select Another Username', 400));
    }
    return next(e);
  }
});

module.exports = router;
