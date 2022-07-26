const bcrypt = require('bcryptjs');
Users = require('../users/users-model');

/*
  If the user does not have a session saved in the server

  status 401
  {
    "message": "You shall not pass!"
  }
*/
function restricted(req, res, next) {
  console.log(!!req.session.chocolatechip, req.session)
  if(!req.session.chocolatechip){
    return res.status(401).json({message: 'You shall not pass!'});
  } else {
    next();
  }
}

/*
  If the username in req.body already exists in the database

  status 422
  {
    "message": "Username taken"
  }
*/
async function checkUsernameFree(req, res, next) {
  const { username, password } = req.body
  if(typeof username === 'string'){
    const result = await Users.findBy({ username: username }).first()
    if(result == null){
      next()
    } else {
      return res.status(422).json({message: 'Username taken'})
    }
  }
}

/*
  If the username in req.body does NOT exist in the database

  status 401
  {
    "message": "Invalid credentials"
  }
*/
async function checkUsernameExists(req, res, next) {
  const { username } = req.body
  if(typeof username === 'string'){
    const result = await Users.findBy({ username: username }).first()
    if(result != null){
      next()
    } else {
      return res.status(401).json({message: 'Invalid credentials'})
    }
  }
}

/*
  If password is missing from req.body, or if it's 3 chars or shorter

  status 422
  {
    "message": "Password must be longer than 3 chars"
  }
*/
function checkPasswordLength(req, res, next) {
  const { username, password } = req.body
  if(typeof password !== 'string' || password.length < 4){
    return res.status(422).json({message: 'password must be longer than 3 chars'})
  }
  next();
}

// Don't forget to add these to the `exports` object so they can be required in other modules
module.exports = {
  restricted,
  checkUsernameFree,
  checkPasswordLength,
  checkUsernameExists
}