const express = require("express"),
  app = express(),
  bodyParser = require("body-parser"),
  mongoose = require("mongoose"),
  sessions = require("client-sessions"),
  bycrypt = require("bcryptjs");

mongoose.set("useNewUrlParser", true);
mongoose.set("useUnifiedTopology", true);
mongoose.set("useFindAndModify", false);
mongoose.set("useCreateIndex", true); // for unique field in the Schema
mongoose.connect("mongodb://localhost:27017/ss-auth");

// Models
let User = new mongoose.model(
  "User",
  new mongoose.Schema({
    firstName: { type: String, required: true },
    lastName: { type: String, required: true },
    // 2 users will not be able to register on the website with the same email
    email: { type: String, required: true, unique: true },
    password: { type: String, required: true },
  })
);

app.set("view engine", "pug");
app.use(bodyParser.urlencoded({ extended: true }));
// the next line gives us the req.session object and lets us add any property we want to it
app.use(
  sessions({
    cookieName: "session",
    secret: "woosafd32532wfsf",
    duration: 30 * 60 * 1000,
  })
);
// middleware
app.use((req, res, next) => {
  // if there si no session data available(aka no cookies) keep the show running
  if (!(req.session && req.session.userId)) {
    return next();
  }
  // if there is a session available
  // this cookie has the user id in it -> give me the user object back
  User.findById(req.session.userId, (err, user) => {
    if (err) {
      return next(err);
    }
    if (!user) {
      return next();
    }
    user.password = undefined;
    // create object req.user
    req.user = user;
    // express -> if you set a var user in the req.locals, in any templates that you have, you automatically have access to that user var
    res.locals.user = user;
    next();
  });
});

// Routes
app.get("/", function (req, res) {
  res.render("index");
});
app.get("/register", function (req, res) {
  res.render("register");
});
app.post("/register", function (req, res) {
  // res.send('POST req succes');
  // res.json(req.body);
  let hash = bycrypt.hashSync(req.body.password, 14);
  req.body.password = hash;
  User.create(req.body, (err, user) => {
    if (err) {
      let error = "Something bad happened! Please try again.";
      if (err.code === 11000) {
        error = "That email is already taken, please try another.";
      }
      res.render("register", { error: error });
    } else {
      req.session.userId = user._id;
      res.redirect("/dashboard");
    }
  });
});

app.get("/login", function (req, res) {
  res.render("login");
});
app.post("/login", function (req, res) {
  User.findOne({ email: req.body.email }, (err, user) => {
    // bycrypt.compareSync - compares the password from the form with the hashed password in the database
    if (!user || !bycrypt.compareSync(req.body.password, user.password)) {
      return res.render("login", { error: "Incorrect email / password" });
    }
    req.session.userId = user._id;
    res.redirect("/dashboard");
  });
});

app.get("/dashboard", function (req, res) {
  if (!(req.session && req.session.userId)) {
    return res.redirect("/login");
  }
  User.findById(req.session.userId, (err, user) => {
    if (err) {
      return next(err);
    }
    if (!user) {
      return res.redirect("/login");
    }
    res.render("dashboard");
  });
});
app.listen(3000, () => console.log("started server on port 3000"));
