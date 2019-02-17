'use strict';
/**
 * middleware.js
 * @module middleware
 */

const User = require('./users-model.js');

/**
 * Exports modules
 * @param {*} req
 * @param {*} res
 * @param {*} next
 * @returns
 */
module.exports = (req, res, next) => {
  
  // Basic am9objpqb2hubnk=
  // Bearer Token ...
  try {
    let [authType, authString] = req.headers.authorization.split(/\s+/);
    
    switch( authType.toLowerCase() ) {
    case 'basic': 
      return _authBasic(authString);
    case 'bearer':
      return _authBearer(authString);
    default: 
      return _authError();
    }
  }
  catch(e) {
    next('Resource Not Available');
  }
  
  
  /**
   * _authBasic function for basic authorization
   * @param {*} str
   * @returns
   */
  function _authBasic(str) {
    // str: am9objpqb2hubnk=
    let base64Buffer = Buffer.from(str, 'base64'); // <Buffer 01 02 ...>
    let bufferString = base64Buffer.toString();    // john:mysecret
    let [username, password] = bufferString.split(':'); // john='john'; mysecret='mysecret']
    let auth = {username,password}; // { username:'john', password:'mysecret' }
    
    return User.authenticateBasic(auth)
      .then(user => _authenticate(user) )
      .catch(next);
  }

  /**
   * _authBearer function for token authentication, user verification
   * @param {*} str
   * @returns
   */
  function _authBearer(str){
    return User.authenticateToken(str)
      .then(user => _authenticate(user))
      .catch(next);
  }

  /**
   * _authenticate function authenticates the user and generates token
   * @param {*} user
   */
  function _authenticate(user) {
    console.log({user});
    if(user) {
      req.user = user;
      req.token = user.generateToken();
      next();
    }
    else {
      _authError();
    }
  }
  
  /**
   *Error function
   */
  function _authError() {
    next('Invalid User ID/Password');
  }
  
};