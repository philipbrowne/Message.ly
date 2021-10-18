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

/** GET /:id - get detail of message.
 *
 * => {message: {id,
 *               body,
 *               sent_at,
 *               read_at,
 *               from_user: {username, first_name, last_name, phone},
 *               to_user: {username, first_name, last_name, phone}}
 *
 * Make sure that the currently-logged-in users is either the to or from user.
 *
 **/

router.get('/:id', authenticateJWT, ensureLoggedIn, async (req, res, next) => {
  try {
    const message = await Message.get(req.params.id);
    if (
      message.to_user.username === req.user.username ||
      message.from_user.username === req.user.username
    ) {
      return res.json(message);
    }
    throw new ExpressError('Unauthorized', 401);
  } catch (e) {
    return next(e);
  }
});
/** POST / - post message.
 *
 * {to_username, body} =>
 *   {message: {id, from_username, to_username, body, sent_at}}
 *
 **/

router.post('/', authenticateJWT, ensureLoggedIn, async (req, res, next) => {
  try {
    const from_username = req.user.username;
    const { to_username, body } = req.body;
    if (!to_username || !body) {
      throw new ExpressError('Invalid request', 400);
    }
    const message = await Message.create({
      from_username,
      to_username,
      body,
    });
    return res.json(message);
  } catch (e) {
    if (e.code === '23503') {
      return next(new ExpressError('Invalid username', 400));
    }
    return next(e);
  }
});

/** POST/:id/read - mark message as read:
 *
 *  => {message: {id, read_at}}
 *
 * Make sure that the only the intended recipient can mark as read.
 *
 **/

router.post(
  '/:id/read',
  authenticateJWT,
  ensureLoggedIn,
  async (req, res, next) => {
    try {
      const message = await Message.get(req.params.id);
      if (message.to_user.username === req.user.username) {
        const readMessage = await Message.markRead(req.params.id);
        return res.json({
          message: readMessage,
        });
      }
      throw new ExpressError('Unauthorized', 401);
    } catch (e) {
      return next(e);
    }
  }
);

module.exports = router;
