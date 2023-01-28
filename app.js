require('dotenv').config();
const express = require("express");
const ejs = require("ejs");
const bodyParser = require("body-parser");
const mongoose = require("mongoose");
const session = require('express-session');
const passport = require("passport");
const passportLocalMongoose = require("passport-local-mongoose");
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const findOrCreate = require("mongoose-findorcreate");
const nocache = require("nocache");

const app = express();

app.use(express.static("public"));
app.set("view engine", "ejs");
app.use(nocache());
app.use(bodyParser.urlencoded({extended: true}));

app.use(session({
    secret:process.env.SECRET,
    resave: false,
    saveUninitialized: false
}));

app.use(passport.initialize());
app.use(passport.session());

main().catch(err => console.log(err));

async function main() {
  mongoose.set("strictQuery", false);
  mongoose.connect("mongodb+srv://admin-aayush:admintest@cluster0.c1vspam.mongodb.net/usersDB");
}

const usersSchema = new mongoose.Schema({
    username: {
        type: String,
        unique: true 
    }, 
    password: String,
    provider: String,
    email: String,
    secret: Array
});

usersSchema.plugin(passportLocalMongoose, {usernameField: "username"});
usersSchema.plugin(findOrCreate);

const User =  mongoose.model("User", usersSchema);

passport.use(User.createStrategy());

passport.serializeUser(function(user, cb) {
    process.nextTick(function() {
      cb(null, { id: user.id, username: user.username, name: user.name });
    });
  });
   
  passport.deserializeUser(function(user, cb) {
    process.nextTick(function() {
      return cb(null, user);
    });
  });

passport.use(new GoogleStrategy({
    clientID: process.env.CLIENT_ID,
    clientSecret: process.env.CLIENT_SECRET,
    callbackURL: "https://secrets-e6ct.onrender.com/auth/google/secrets"
  },
  function(accessToken, refreshToken, profile, cb) {
    User.findOrCreate({ username: profile.id },
        {provider: "google", 
        email: profile._json.email
    }, 
    function (err, user) {
      return cb(err, user);
    });
  }
));


app.get("/", function(req, res){
    res.render("home");
});

app.get("/auth/google", 
    passport.authenticate("google", {scope: ["profile", "email"]}));

app.get("/auth/google/secrets",
  passport.authenticate('google', { failureRedirect: '/login', failureMessage: true }),
  function(req, res) {
    res.redirect("/secrets");
  });

app.get("/login", function(req, res){
    res.render("login");
});

app.get("/register", function(req, res){
    res.render("register");
});

app.get("/secrets", (req, res) => {
  if(req.isAuthenticated()){
    User.find({secret:{$ne:null}},function (err, users){
      if(!err){
        if (users){
          res.render("secrets",{usersWithSecrets:users});
        }else {
          console.log(err);
        }
      }else {
        console.log(err);
      }
    });
}else {
        res.redirect("/");
      }
});

        

app.route("/submit")

    .get(function (req,res){
      if(req.isAuthenticated()){
        User.findById(req.user.id,function (err,foundUser){
          if(!err){
            res.render("submit",{secrets:foundUser.secret});
          }
        })
      }else {
        res.redirect("/login");
      }
    })

    .post(function (req, res){
      if(req.isAuthenticated()){
        User.findById(req.user.id,function (err, user){
          user.secret.push(req.body.secret);
          user.save(function (){
            res.redirect("/secrets");
          });
        });
     
      }else {
       res.redirect("/login");
      }
});

app.post("/submit/delete",function (req, res){
  if(req.isAuthenticated()){
    User.findById(req.user.id, function (err,foundUser){
      foundUser.secret.splice(foundUser.secret.indexOf(req.body.secret),1);
      foundUser.save(function (err) {
        if(!err){
          res.redirect("/submit");
        }
      });
    });
  }else {
    res.redirect("/login");
  }
});
     
app.get('/logout', function(req, res) {
  req.logout(function(err) {
    if (err) {
      console.log(err);
    }
    res.redirect('/');
  });
});
     

app.post("/register", function(req, res){
  const username = req.body.username;
  const password = req.body.password;

  User.register({ username: username, email: username, provider: 'local' }, password, function(err, user) {
    if (err) {
      console.log(err);
      res.redirect('/register');
    } else {
      passport.authenticate('local')(req, res, function() {
        res.redirect('/secrets');
      });
    }
  });
});

// Login Process
app.post('/login', function (req, res) {
  const logUser = new User ({
      username: req.body.username,
      password: req.body.password
  })

  passport.authenticate('local')(req, res, function () {
      req.logIn(logUser, function (err) {
          if (err) {
              console.log(err);
          }
      })
      res.redirect('/secrets')
  })
});





app.listen(3000, function(req, res){
    console.log("Server started on port 3000");
})
