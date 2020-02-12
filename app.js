//jshint esversion:6
//require("dotenv").config();
const express = require("express");
const bodyParser = require("body-parser");
const ejs = require("ejs");
const mongoose = require("mongoose");
const encrypt = require("mongoose-encryption");
const md5 = require("md5");
const bcrypt = require("bcrypt");
const saltRounds = 10;

const app = express();

app.use(express.static("public"));
app.set("view engine", "ejs");
app.use(bodyParser.urlencoded({ extended: true }));

mongoose.connect("mongodb://localhost:27017/userDB", { useNewUrlParser: true });

const userSchema = new mongoose.Schema({
  email: String,
  password: String
});

// const secret = process.env.SECRET;
// console.log("This is " + secret);

// add the encrpt plugin before creating the model
// userSchema.plugin(encrypt, { secret: secret, encryptedFields: ["password"] });

const User = new mongoose.model("User", userSchema);

app.get("/", (req, res) => {
  res.render("home");
});

app.get("/login", (req, res) => {
  res.render("login");
});

app.get("/register", (req, res) => {
  res.render("register");
});

app.post("/register", (req, res) => {
  console.log("Passowrd is" + req.body.password);
  bcrypt.hash(req.body.password, saltRounds, (err, hash) => {
    if (!err) {
      const newUser = new User({
        email: req.body.username,
        password: hash
      });
      newUser.save(err => {
        if (!err) {
          res.render("secrets");
        } else {
          console.log(err);
        };
      });
    }else{
    res.render(err);}
  });
});

app.post("/login", (req, res) => {
  const username = req.body.username;
  const password = req.body.password;

  User.findOne({ email: username }, (err, result) => {
    if (!err) {
      if (result) {
        bcrypt.compare(password, result.password, (err, respond) => {
          if(!err){
            if (respond === true) {
              res.render("secrets");
            };
          }else{
            res.render(err);
          };
        });
      }
    } else {
      res.render("Something went wrong" + err);
    }
  });
});

app.listen(3000, () => {
  console.log("We are connected!");
});
