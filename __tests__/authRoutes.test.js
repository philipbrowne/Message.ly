const request = require('supertest');
const jwt = require('jsonwebtoken');

const app = require('../app');
const db = require('../db');
const User = require('../models/user');

describe('Auth Routes Test', function () {
  beforeEach(async function () {
    await db.query('DELETE FROM messages');
    await db.query('DELETE FROM users');

    let u1 = await User.register({
      username: 'test15',
      password: 'password',
      first_name: 'Test15',
      last_name: 'Testy15',
      phone: '+14155550000',
    });
  });

  /** POST /auth/register => token  */

  describe('POST /auth/register', function () {
    test('can register', async function () {
      let response = await request(app).post('/auth/register').send({
        username: 'bob',
        password: 'secret',
        first_name: 'Bob',
        last_name: 'Smith',
        phone: '+14150000000',
      });

      let token = response.body.token;
      expect(jwt.decode(token)).toEqual({
        username: 'bob',
        iat: expect.any(Number),
      });
    });
  });

  /** POST /auth/login => token  */

  describe('POST /auth/login', function () {
    test('can login', async function () {
      let response = await request(app)
        .post('/auth/login')
        .send({ username: 'test15', password: 'password' });

      let token = response.body.token;
      expect(jwt.decode(token)).toEqual({
        username: 'test15',
        iat: expect.any(Number),
      });
    });

    test("won't login w/wrong password", async function () {
      let response = await request(app)
        .post('/auth/login')
        .send({ username: 'test15', password: 'WRONG' });
      expect(response.statusCode).toEqual(400);
    });

    test("won't login w/wrong password", async function () {
      let response = await request(app)
        .post('/auth/login')
        .send({ username: 'not-user', password: 'password' });
      expect(response.statusCode).toEqual(400);
    });
  });
});
afterEach(async function () {
  // delete any data created by test
  await db.query('DELETE FROM users');
});

afterAll(async function () {
  await db.end();
});
