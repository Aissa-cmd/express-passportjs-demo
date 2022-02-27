const express = require("express");
const passport = require("passport");
const bcrypt = require("bcrypt");
const flash = require("express-flash");
const session = require("express-session");

const LocalStrategy = require("passport-local").Strategy;

const app = express();

const users = [];

// done(error, user, {message: ''})

passport.use(
  new LocalStrategy({ usernameField: "email" }, async function (
    email,
    password,
    done
  ) {
    const user = users.find((user) => user.email === email);
    if (user == null) {
      return done(null, false, { message: "No user with that email" });
    }

    try {
      if (await bcrypt.compare(password, user.password)) {
        return done(false, user);
      } else {
        return done(null, false, { message: "password incorrect" });
      }
    } catch (error) {
      return done(error);
    }
  })
);

function checkAuthenticated(req, res, next) {
  if (req.isAuthenticated()) {
    return next();
  }
  res.redirect("/login");
}

function checkNotAuthenticated(req, res, next) {
  if (req.isAuthenticated()) {
    return res.redirect("/");
  }
  next();
}

function getUserById(id) {
  return users.find((user) => user.id === id);
}

passport.serializeUser((user, done) => done(null, user.id));
passport.deserializeUser((id, done) => done(null, getUserById(id)));

app.set("view engine", "ejs");
app.use(express.urlencoded({ extended: false }));
app.use(flash());
app.use(
  session({
    secret: "skldjfalksdjflasjdfa",
    resave: false,
    saveUninitialized: false,
  })
);
app.use(passport.initialize());
app.use(passport.session());

app.get("/", checkAuthenticated, (req, res) => {
  res.render("index.ejs", { user: req.user });
});

app.get("/login", checkNotAuthenticated, (req, res) => {
  res.render("login.ejs");
});

app.post(
  "/login",
  passport.authenticate("local", {
    successRedirect: "/",
    failureRedirect: "/login",
    failureFlash: true,
  })
);

app.get("/register", checkNotAuthenticated, (req, res) => {
  res.render("register.ejs");
});

app.post("/register", async (req, res) => {
  try {
    const hashedPassword = await bcrypt.hash(req.body.password, 10);

    users.push({
      id: Date.now().toString(),
      name: req.body.name,
      email: req.body.email,
      password: hashedPassword,
    });

    res.redirect("/login");
  } catch (error) {
    res.redirect("/register");
  }

  console.log("users", users);
});

app.post("/logout", (req, res) => {
  req.logout();
  res.redirect("/login");
});

app.listen(3000, () => {
  console.log("Server is running on port 3000");
});
