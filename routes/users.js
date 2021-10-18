const express = require('express');
const router = new express.Router();
const ExpressError = require('../expressError');
const User = require('../models/user');
const {
  ensureLoggedIn,
  ensureCorrectUser,
  authenticateJWT,
} = require('../middleware/auth');

/** GET / - get list of users.
 *
 * => {users: [{username, first_name, last_name, phone}, ...]}
 *
 **/

router.get('/', authenticateJWT, ensureLoggedIn, async (req, res, next) => {
  try {
    const users = await User.all();
    return res.json({ users: users });
  } catch (e) {
    return next(e);
  }
});

/** GET /:username - get detail of users.
 *
 * => {user: {username, first_name, last_name, phone, join_at, last_login_at}}
 *
 **/

router.get(
  '/:username',
  authenticateJWT,
  ensureLoggedIn,
  ensureCorrectUser,
  async (req, res, next) => {
    try {
      const user = await User.get(req.params.username);
      if (user) {
        return res.json({ user: user });
      }
      throw new ExpressError('Username not found', 404);
    } catch (e) {
      return next(e);
    }
  }
);

/** GET /:username/to - get messages to user
 *
 * => {messages: [{id,
 *                 body,
 *                 sent_at,
 *                 read_at,
 *                 from_user: {username, first_name, last_name, phone}}, ...]}
 *
 **/

router.get(
  '/:username/to',
  authenticateJWT,
  ensureLoggedIn,
  ensureCorrectUser,
  async (req, res, next) => {
    try {
      const messages = await User.messagesTo(req.params.username);
      if (messages) {
        return res.json({ messages: messages });
      }
      throw new ExpressError('No Messages Found', 404);
    } catch (e) {
      return next(e);
    }
  }
);

/** GET /:username/from - get messages from user
 *
 * => {messages: [{id,
 *                 body,
 *                 sent_at,
 *                 read_at,
 *                 to_user: {username, first_name, last_name, phone}}, ...]}
 *
 **/

router.get(
  '/:username/from',
  authenticateJWT,
  ensureLoggedIn,
  ensureCorrectUser,
  async (req, res, next) => {
    try {
      const messages = await User.messagesFrom(req.params.username);
      if (messages) {
        return res.json({ messages: messages });
      }
      throw new ExpressError('No Messages Found', 404);
    } catch (e) {
      return next(e);
    }
  }
);

module.exports = router;
