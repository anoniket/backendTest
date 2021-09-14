const express = require("express");
const mongoose = require("mongoose");
const bodyParser = require("body-parser");
const bcrypt = require("bcrypt");
const saltRounds = 10;
const jwt = require("jsonwebtoken");
const e = require("express");
require("dotenv").config();

var token = jwt.sign(
  {
    exp: Math.floor(Date.now() / 1000) + 60 * 60,
    data: "foobar",
  },
  "secret"
);

const app = express();
app.use(
  bodyParser.urlencoded({
    extended: true,
  })
);

mongoose.connect(process.env.MONGO_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true,
});
const db = mongoose.connection;
db.on("error", console.error.bind(console, "connection error:"));
db.once("open", function () {
  console.log("Einates have captured mongoose");
});

const userSchema = new mongoose.Schema({
  email: String,
  name: String,
  password: String,
});

const User = new mongoose.model("User", userSchema);

app.post("/signup", function (req, res) {
  const { name, email, password } = req.body;
  if (!(email && password && name)) {
    res.status(400).send("All input is required");
  } else {
    User.findOne({ email: req.body.email }, function (err, user) {
      if (err) {
        res.status(400).send(err);
      } else if (user) {
        res.json({
          message:
            "User with this email already exists. Please use another one.",
        });
      } else {
        bcrypt.hash(req.body.password, saltRounds, function (err, hash) {
          if (!err) {
            var user = new User({
              name: req.body.name,
              email: req.body.email,
              password: hash,
            });

            user
              .save()
              .then((user) => {
                res.status(200).send("User successfully registered");
              })
              .catch((err) => {
                res.status(400).send(err);
              });
          } else if (err) {
            res.status(400).send(err);
          }
        });
      }
    });
  }
});

app.post("/login", function (req, res) {
  const { email, password } = req.body;

  if (!(email && password)) {
    res.status(400).send("All input is required");
  } else {
    User.findOne({ email: req.body.email }, function (err, user) {
      if (!user) {
        res.status(400).send("No user found");
      } else if (user) {
        bcrypt.compare(
          req.body.password,
          user.password,
          function (err, result) {
            if (err) {
              res.status(400).send(err);
            } else if (result) {
              const jwtoken = jwt.sign({ id: user.email }, token, {
                expiresIn: "2h",
              });
              res.json({
                user: user,
                token: jwtoken,
              });
            } else {
              res.status(400).send("Password is wrong, " + user.name);
            }
          }
        );
      } else if (err) {
        res.status(400).send(err);
      }
    });
  }
});

app.post("/home", function (req, res) {
  const authHeader = req.headers["authorization"];
  const btoken = authHeader && authHeader.split(" ")[1];

  if (!btoken) {
    return res.status(403).send("A token is required for authentication");
  }
  try {
    const decoded = jwt.verify(btoken, token);
    User.findOne({ email: decoded.id }, function (err, user) {
      if (user) {
        res.json({ success: true, user: user });
      } else if (err) {
        res.status(400).send(err);
      }
    });
  } catch (err) {
    return res.status(401).send("Invalid Token");
  }
});

app.listen(process.env.port || 5000, function () {
  console.log("Einates at your service Master!");
});
