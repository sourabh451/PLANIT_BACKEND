let express = require("express");
let userRouter = express.Router();
let { UserModel } = require("../model/user.model");
let jwt = require("jsonwebtoken");
let bcrypt = require("bcrypt");

// Validation functions
function isValidEmail(email) {
  const emailRegex = /[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,3}$/i;
  return emailRegex.test(email);
}

function isValidPassword(password) {
  const passwordRegex =
    /^(?=[\s\S]{8,32}$)(?=[\s\S]*[A-Z])(?=[\s\S]*[a-z])(?=[\s\S]*[0-9])(?=[\s\S]*[!@#$%^&*])[\s\S]*/;
  return passwordRegex.test(password);
}

function isValidFull_name(full_name) {
  const full_nameRegex = /^([a-zA-Z]{2,20})+(?:\s([a-zA-Z]{2,20})+)+$/;
  return full_nameRegex.test(full_name);
}

function isValidAccount_name(account_name) {
  const account_nameRegex = /^([A-z]{2,20})*$|^([A-z]+\s[A-z]{2,20})*$/;
  return account_nameRegex.test(account_name);
}

// register/signup
userRouter.post("/register", async (req, res) => {
  let { email, password, full_name, account_name } = req.body;

  // Validate full name
  if (!isValidFull_name(full_name)) {
    res.status(400).send({ msg: "Invalid full name." });
    return;
  }

  // Validate email
  if (!isValidEmail(email)) {
    res.status(400).send({ msg: "Invalid email address." });
    return;
  }

  // Validate password
  if (!isValidPassword(password)) {
    res.status(400).send({ msg: "Invalid password." });
    return;
  }

  // Validate account name
  if (!isValidAccount_name(account_name)) {
    res.status(400).send({ msg: "Invalid account name" });
    return;
  }
  if (password.length < 8) {
    res
      .status(400)
      .send({ msg: "Password must be at least 8 characters long." });
  }
  try {
    bcrypt.hash(password, 5, async (err, hash) => {
      if (err) {
        res.status(500).send({ msg: "Error hashing password." });
        return;
      }
      let user = new UserModel({
        email,
        password: hash,
        full_name,
        account_name,
      });
      await user.save();
      res.status(200).send({ msg: "Registration Successful" });
    });
  } catch (error) {
    res.status(400).send({ error: "Registration failed", msg: error.message });
  }
});

// login
userRouter.post("/login", async (req, res) => {
  let { email, password } = req.body;
  try {
    let user = await UserModel.find({ email });
    if (user.length > 0) {
      bcrypt.compare(password, user[0].password, (err, result) => {
        if (result) {
          res.status(200).send({
            msg: "Login successful",
            token: jwt.sign({ userID: user[0]._id }, "planit"),
            email: user[0].email,
          });
        } else {
          res.status(400).send({ msg: "wrong Password" });
        }
      });
    } else {
      res.status(400).send({ msg: "Email not found" });
    }
  } catch (error) {
    res.status(400).send({ msg: error.message });
  }
});

module.exports = {
  userRouter,
};
