const jwt = require('jsonwebtoken');
const config = require('config');
const chalk = require('chalk');

function auth(req, res, next) {
  const token = req.header('malcom-auth-token');
  if (!token) {
    console.log(chalk.red('Access denied, No token provided'));
    return res.status(401).send('Access denied. No token provided.');
  }


  try {
    const decoded = jwt.verify(token, config.get('jwtPrivateKey'));
    req.user = decoded;
    console.log(chalk.green('Valid Token'));
    next();
  } catch (ex) {
    console.log(chalk.red('Invalid Token'));
    res.status(400).send('Invalid token.');
  }
}


function admin(req, res, next) {
  // 401 Unauthorized
  // 403 Forbidden 

  if (!req.user.isAdmin) {
    console.log(chalk.red('Access denied, PRIVILEGE escalation issues'));
    return res.status(403).send('Access denied.');
  }

  console.log(chalk.green('Admin Access Granted'));
  next();
}

module.exports = {
  auth,
  admin
}