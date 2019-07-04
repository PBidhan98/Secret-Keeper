//jshint esversion:6

require('dotenv').config();
const express = require("express");
const bodyParser = require("body-parser");
const ejs = require("ejs");
const mongoose = require('mongoose');
const session = require('express-session');
const passport = require('passport');
const passportLocalMongoose = require('passport-local-mongoose');

const app = express();

app.set('view engine', 'ejs');
app.use(bodyParser.urlencoded({
  extended: true
}));
app.use(express.static("public"));

app.use(session({
  secret: "Our little secret.",
  resave: false,
  saveUninitialized: false
}));

//initialized passport
app.use(passport.initialize());
//used passport to manage our sessions
app.use(passport.session());

mongoose.connect("mongodb://localhost:27017/userDB", {
  useNewUrlParser: true
});

mongoose.set("useCreateIndex", true);

const userSchema = new mongoose.Schema({
  email: String,
  password: String
});

userSchema.plugin(passportLocalMongoose);

const User = new mongoose.model("User", userSchema);

//passport authentication fo local login security
passport.use(User.createStrategy());

passport.serializeUser(User.serializeUser());
passport.deserializeUser(User.deserializeUser());
//serialize is neccessary when we use sessions
//on serializing, it creates the fortune cookie and stuffs the message, users identification
//on deserialise, it allows passport to crumble the cookie and discover the message inside which is who this user is.. so that we can authenticate them on our server

app.get("/", function(req, res) {
  res.render("home");
});

app.get("/login", function(req, res) {
  res.render("login");
});

app.get("/register", function(req, res) {
  res.render("register");
});

app.get("/secrets", function(req, res) {
  if(req.isAuthenticated()){
    res.render("secrets");
  }else{
    res.redirect("/login");
  }
});

//passport js log out function
app.get("/logout", function(req,res){
  req.logout();
  res.redirect("/");
});

app.post("/register", function(req, res) {

//passpot-local-mongose package
  User.register({username: req.body.username}, req.body.password, function(err, user){
    if(err){
      console.log(err);
      res.redirect("/register");
    }else{
      passport.authenticate("local")(req, res, function(){
//for setting loggedin session for user, so even if they go directly to the secrets page they should automatically be able to view it, if they are infact still logged in.
        res.redirect("/secrets");
      });
    }
  });

});

app.post("/login", function(req, res) {

  const user = new User({
    username: req.body.username,
    password: req.body.password
  });
//use passport to login the user and authenticate
  req.login(user, function(err){
    if(err){
      console.log(err);
    }else{
      passport.authenticate("local")(req, res, function(){
          //for setting loggedin session for user, so even if they go directly to the secrets page they should automatically be able to view it, if they are infact still logged in.
        res.redirect("/secrets");
      });
    }
  })

});


app.listen(3000, function() {
  console.log("Server started on port 3000");
});
