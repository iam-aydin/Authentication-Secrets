// Import necessary modules and configure environment variables
require("dotenv").config();
const bodyParser = require("body-parser");
const express = require("express");
const ejs = require("ejs");
const mongoose = require("mongoose");
const session = require("express-session");
const LocalStrategy = require("passport-local").Strategy;
const passport = require("passport");
const passportLocalMongoose = require("passport-local-mongoose");
const GoogleStrategy = require("passport-google-oauth20").Strategy;
const findOrCreate = require("mongoose-findorcreate");
const FacebookStrategy = require("passport-facebook").Strategy;

// Initialize Express application
const app = express();

// Connect to MongoDB database
mongoose
  .connect(process.env.MONGODB_URI)
  .then(() => console.log("Connected to MongoDB"))
  .catch((err) => console.error("Failed to connect to MongoDB", err));

// Define user schema and plugin for Passport authentication
const userSchema = new mongoose.Schema({
  email: String,
  password: String,
  googleId: String,
  facebookId: String,
  secret: String,
});

userSchema.plugin(passportLocalMongoose);
userSchema.plugin(findOrCreate);

// Configure middleware for serving static files and setting view engine
app.use(express.static("public"));
app.set("view engine", "ejs");
app.use(bodyParser.urlencoded({ extended: true }));

// Set up session management for Passport
app.use(
  session({
    secret: "Our little Secret.",
    resave: false,
    saveUninitialized: false,
  })
);

// Initialize Passport and its session handling
app.use(passport.initialize());
app.use(passport.session());

// Create User model based on the defined schema
const User = new mongoose.model("User", userSchema);

// Configures Passport to use a local strategy for authentication
passport.use(new LocalStrategy(User.authenticate()));

// Serialize and deserialize user instances to and from the session
passport.serializeUser(function (user, done) {
  done(null, user._id);
  // if you use Model.id as your idAttribute maybe you'd want
  // done(null, user.id);
});

passport.deserializeUser(function (id, done) {
  User.findById(id)
    .then((user) => {
      done(null, user);
    })
    .catch(done);
});

passport.use(
  new FacebookStrategy(
    {
      clientID: process.env.FACEBOOK_APP_ID,
      clientSecret: process.env.FACEBOOK_APP_SECRET,
      callbackURL: "http://localhost:3000/auth/facebook/callback",
    },
    function (accessToken, refreshToken, profile, cb) {
      User.findOrCreate({ facebookId: profile.id }, function (err, user) {
        return cb(err, user);
      });
    }
  )
);

passport.use(
  new GoogleStrategy(
    {
      clientID: process.env.CLIENT_ID,
      clientSecret: process.env.CLIENT_SECRET,
      callbackURL: "http://localhost:3000/auth/google/secrets",
      userProfile: "https://www.googleapis.com/oauth2/userinfo",
    },
    function (accessToken, refreshToken, profile, cb) {
      console.log(profile);

      User.findOrCreate({ googleId: profile.id }, function (err, user) {
        return cb(err, user);
      });
    }
  )
);

// Define routes for the application
app.get("/", function (req, res) {
  res.render("home");
});

app.get("/login", function (req, res) {
  res.render("login");
});

app.get("/register", function (req, res) {
  res.render("register");
});

// Route for displaying secrets
app.get("/secrets", function (req, res) {
  User.find({ secret: { $ne: null } })
    .then((foundUsers) => {
      if (foundUsers) {
        res.render("secrets", { usersWithSecrets: foundUsers });
      }
    })
    .catch((err) => {
      console.log(err);
    });
});

// Route for submitting content
app.get("/submit", (req, res) => {
  if (req.isAuthenticated()) {
    res.render("submit");
  } else {
    res.redirect("login");
  }
});

// Handle user logout
app.get("/logout", function (req, res) {
  req.logout((err) => {
    if (err) {
      console.log(err);
    }
  });
  res.redirect("/");
});

// Route for initiating Google OAuth process
app.get("/auth/google", function (req, res) {
  passport.authenticate("google", { scope: ["profile"] })(req, res);
});

// Callback route for handling Google OAuth result
app.get(
  "/auth/google/secrets",
  passport.authenticate("google", { failureRedirect: "/login" }),
  function (req, res) {
    // Successful authentication, redirect home.
    res.redirect("/secrets");
  }
);

// Route for initiating Facebook OAuth process
app.get("/auth/facebook", passport.authenticate("facebook"));

// Callback route for handling Facebook OAuth result
app.get(
  "/auth/facebook/callback",
  passport.authenticate("facebook", { failureRedirect: "/login" }),
  function (req, res) {
    // Successful authentication, redirect home.
    res.redirect("/secrets");
  }
);

// Handle user registration
app.post("/register", function (req, res) {
  User.register(
    { username: req.body.username },
    req.body.password,
    function (err, user) {
      if (err) {
        console.log(err);
        res.redirect("register");
      } else {
        // Authenticates the newly registered user
        passport.authenticate("local")(req, res, function () {
          res.redirect("/secrets");
        });
      }
    }
  );
});

// Handle user login
app.post("/login", async function (req, res) {
  const user = new User({
    username: req.body.username,
    password: req.body.password,
  });

  req.login(user, (err) => {
    // Attempts to log in the user using Passport
    if (err) {
      console.log(err);
    } else {
      passport.authenticate("local")(req, res, function () {
        // Authenticates the user locally
        res.redirect("/secrets");
      });
    }
  });
});

// Handles submission of a secret
app.post("/submit", (req, res) => {
  const submittedSecret = req.body.secret;

  // Retrieve user by ID and update their secret
  User.findById(req.user.id)
    .then((foundUser) => {
      if (foundUser) {
        foundUser.secret = submittedSecret;
        return foundUser.save();
      }
    })
    // Redirect to secrets page after successful save
    .then(() => {
      res.redirect("/secrets");
    })
    // Handle any errors
    .catch((err) => {
      console.log(err);
    });
});

// Starts the server on port  3000
app.listen(3000, function () {
  console.log("Server started on port  3000: http://localhost:3000/");
});
