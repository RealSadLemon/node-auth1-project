// Require `checkUsernameFree`, `checkUsernameExists` and `checkPasswordLength`
// middleware functions from `auth-middleware.js`. You will need them here!
const { checkPasswordLength, checkUsernameExists, checkUsernameFree, restricted } = require('./auth-middleware')
const express = require('express')
const router = express.Router();
const Users = require('../users/users-model')
const bcrypt = require('bcryptjs')

router.post('/register', checkPasswordLength, checkUsernameFree, async (req, res, next) => {
  const { username, password } = req.body;

  const hashPass = await bcrypt.hash(password, 10)
  Users.add({username, password: hashPass})
    .then((user) => {
      res.status(200).json(user)
    })
})
/**
  1 [POST] /api/auth/register { "username": "sue", "password": "1234" }

  response:
  status 200
  {
    "user_id": 2,
    "username": "sue"
  }

  response on username taken:
  status 422
  {
    "message": "Username taken"
  }

  response on password three chars or less:
  status 422
  {
    "message": "Password must be longer than 3 chars"
  }
 */

router.post('/login', checkUsernameExists, async (req, res, next) => {
  try {
    const { username, password } = req.body;
    
    console.log(username, password, req.body)

    const result = await Users.findBy({ username }).first();

    const passIsNotCorrect = !bcrypt.compareSync(password, result.password) 

    if(result == null || passIsNotCorrect){
      return res.status(401).json({ message: 'Invalid credentials' })
    }

    req.session.chocolatechip = result;

    res.status(200).json({ message: `Welcome ${username}!`})
  } catch(err) {
    next(err);
  }
})
/**
  2 [POST] /api/auth/login { "username": "sue", "password": "1234" }

  response:
  status 200
  {
    "message": "Welcome sue!"
  }

  response on invalid credentials:
  status 401
  {
    "message": "Invalid credentials"
  }
 */


/**
  3 [GET] /api/auth/logout

  response for logged-in users:
  status 200
  {
    "message": "logged out"
  }

  response for not-logged-in users:
  status 200
  {
    "message": "no session"
  }
 */
router.get('/logout', (req, res, next) => {
  if(req.session.chocolatechip){
    req.session.destroy(err => {
      if(err) {
        next(err);
      } else {
        res.status(200).json({message: 'logged out'})
      }
      console.log(req.session)
    })
  } else {
    return res.status(200).json({message: 'no session'})
  }
})

 
// Don't forget to add the router to the `exports` object so it can be required in other modules
module.exports = router;