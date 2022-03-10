const router = require("express").Router();
const { checkUsernameExists, validateRoleName } = require('./auth-middleware');
const { JWT_SECRET } = require("../secrets"); // use this secret!
const bcryptjs = require('bcryptjs');
const jwt = require('jsonwebtoken');
const Users = require('../users/users-model');

router.post("/register", validateRoleName, (req, res, next) => {
  /**
    [POST] /api/auth/register { "username": "anna", "password": "1234", "role_name": "angel" }

    response:
    status 201
    {
      "user"_id: 3,
      "username": "anna",
      "role_name": "angel"
    }
   */
  const { username, password } = req.body

  if(!username || !password) {
    next({ status: 400, message: "Please provide a username and password"
    })
  } else {
    
    const hash = bcryptjs.hashSync(password, 10);
    
    Users.add({ ...req.body, password: hash })
    .then(user => {
      res.status(201).json(user);
    })
    .catch(err => {
      res.status(500).json({ message: err.message })
    })
  }
});


router.post("/login", checkUsernameExists, (req, res, next) => {
  /**
    [POST] /api/auth/login { "username": "sue", "password": "1234" }

    response:
    status 200
    {
      "message": "sue is back!",
      "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.ETC.ETC"
    }

    The token must expire in one day, and must provide the following information
    in its payload:

    {
      "subject"  : 1       // the user_id of the authenticated user
      "username" : "bob"   // the username of the authenticated user
      "role_name": "admin" // the role of the authenticated user
    }
   */
  const { username, password } = req.body;

  if (!username || !password) {
    next({ status: 400, message: "Please provide a username and password"
    })
  } else {
    const user = req.user
    
    if (bcryptjs.compareSync(password, user.password)) {
      const token = buildToken(user)
      next({ status: 200, message: `${user.username} is back`, token })
    } else {
      next({ status: 401, message: "Invalid credentials" })
    }
  }
});

function buildToken(user) {
  const payload = {
    subject: user.user_id,
    username: user.username,
    role_name: user.role_name
  }
  const options = {
    expiresIn: '1d'
  }

  return jwt.sign(payload, JWT_SECRET, options)
}

module.exports = router;
