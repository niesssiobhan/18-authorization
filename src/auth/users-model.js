'use strict';

const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const faker = require('faker');

const SINGLE_USE_TOKENS = !!process.env.SINGLE_USE_TOKENS;
const TOKEN_EXPIRE = process.env.TOKEN_LIFETIME || 60;
const SECRET = process.env.SECRET || 'foobar';

let timer = setInterval(() => {faker.random.word().toString}, 60000);

const usedTokens = new Set();

const users = new mongoose.Schema({
  username: {type:String, required:true, unique:true},
  password: {type:String, required:true},
  email: {type: String},
  role: {type: String, default:'user', enum: ['admin','editor','user']},
});

users.pre('save', function(next) {
  bcrypt.hash(this.password, 10)
    .then(hashedPassword => {
      this.password = hashedPassword;
      next();
    })
    .catch(console.error);
});

users.statics.createFromOauth = function(email) {

  if(! email) { return Promise.reject('Validation Error'); }

  return this.findOne( {email} )
    .then(user => {
      if( !user ) { throw new Error('User Not Found'); }
      console.log('Welcome Back', user.username);
      return user;
    })
    .catch( error => {
      console.log('Creating new user');
      let username = email;
      let password = 'none';
      return this.create({username, password, email});
    });

};

users.statics.authenticateToken = function(token) {
  let parsedToken = jwt.verify(token, process.env.SECRET);
  let query = {_id:parsedToken.id};
  return this.findOne(query);
};

users.statics.authenticateBasic = function(auth) {
  let query = {username:auth.username};
  return this.findOne(query)
    .then( user => user && user.comparePassword(auth.password) )
    .catch(error => {throw error;});
};

users.methods.comparePassword = function(password) {
  return bcrypt.compare( password, this.password )
    .then( valid => valid ? this : null);
};

users.methods.generateToken = function(type) {
  
  let token = {
    id: this._id,
    role: this.role,
    type: type || 'user',
  };
  
  return jwt.sign(token, process.env.SECRET, { expiresIn: 60 }); 
};

users.methods.generateKey = function() {
  return this.generateToken('key');
};

module.exports = mongoose.model('users', users);