const ExpressError = require('../expressError');
const db = require('../db');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const { SECRET_KEY, BCRYPT_WORK_FACTOR } = require('../config');

/** User class for message.ly */

/** User of the site. */

class User {
  /** register new user -- returns
   *    {username, password, first_name, last_name, phone}
   */

  static async register({ username, password, first_name, last_name, phone }) {
    // Hash Password with Bcrypt
    const hashedPW = await bcrypt.hash(password, BCRYPT_WORK_FACTOR);
    // Save to Database
    const results = await db.query(
      `INSERT INTO users 
      (username, password, first_name, last_name, phone, join_at, last_login_at)
      VALUES ($1, $2, $3, $4, $5, $6, $7)
      RETURNING username, password, first_name, last_name, phone, join_at`,
      [username, hashedPW, first_name, last_name, phone, new Date(), new Date()]
    );
    return results.rows[0];
  }

  /** Authenticate: is this username/password valid? Returns boolean. */

  static async authenticate(username, password) {
    const results = await db.query(
      `SELECT username, password FROM users WHERE username=$1`,
      [username]
    );
    const user = results.rows[0];
    if (user) {
      if (await bcrypt.compare(password, user.password)) {
        return true;
      }
    }
    return false;
  }

  /** Update last_login_at for user */

  static async updateLoginTimestamp(username) {
    const lastLogin = new Date();
    await db.query(`UPDATE users SET last_login_at=$1 WHERE username=$2`, [
      lastLogin,
      username,
    ]);
  }

  /** All: basic info on all users:
   * [{username, first_name, last_name, phone}, ...] */

  static async all() {
    const results = await db.query(
      `SELECT username, first_name, last_name, phone FROM users`
    );
    return results.rows;
  }

  /** Get: get user by username
   *
   * returns {username,
   *          first_name,
   *          last_name,
   *          phone,
   *          join_at,
   *          last_login_at } */

  static async get(username) {
    const results = await db.query(
      `SELECT username, first_name, last_name, phone, join_at, last_login_at FROM users WHERE username=$1`,
      [username]
    );
    return results.rows[0];
  }

  /** Return messages from this user.
   *
   * [{id, to_user, body, sent_at, read_at}]
   *
   * where to_user is
   *   {username, first_name, last_name, phone}
   */

  static async messagesFrom(username) {
    const result = await db.query(
      `SELECT m.id,
                m.from_username,
                f.first_name AS from_first_name,
                f.last_name AS from_last_name,
                f.phone AS from_phone,
                m.to_username,
                t.first_name AS to_first_name,
                t.last_name AS to_last_name,
                t.phone AS to_phone,
                m.body,
                m.sent_at,
                m.read_at
          FROM messages AS m
            JOIN users AS f ON m.from_username = f.username
            JOIN users AS t ON m.to_username = t.username
          WHERE m.from_username = $1`,
      [username]
    );
    const m = result.rows.map((row) => ({
      id: row.id,
      body: row.body,
      read_at: row.read_at,
      sent_at: row.sent_at,
      to_user: {
        username: row.to_username,
        first_name: row.to_first_name,
        last_name: row.to_last_name,
        phone: row.to_phone,
      },
    }));
    return m;
  }

  /** Return messages to this user.
   *
   * [{id, from_user, body, sent_at, read_at}]
   *
   * where from_user is
   *   {username, first_name, last_name, phone}
   */

  static async messagesTo(username) {
    const result = await db.query(
      `SELECT m.id,
                m.from_username,
                f.first_name AS from_first_name,
                f.last_name AS from_last_name,
                f.phone AS from_phone,
                m.to_username,
                t.first_name AS to_first_name,
                t.last_name AS to_last_name,
                t.phone AS to_phone,
                m.body,
                m.sent_at,
                m.read_at
          FROM messages AS m
            JOIN users AS f ON m.from_username = f.username
            JOIN users AS t ON m.to_username = t.username
          WHERE m.to_username = $1`,
      [username]
    );
    const m = result.rows.map((row) => ({
      id: row.id,
      body: row.body,
      read_at: row.read_at,
      sent_at: row.sent_at,
      from_user: {
        username: row.from_username,
        first_name: row.from_first_name,
        last_name: row.from_last_name,
        phone: row.from_phone,
      },
    }));
    return m;
  }
}

module.exports = User;
