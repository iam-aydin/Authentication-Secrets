// Import necessary modules and configure environment variables
require("dotenv").config(); // Load environment variables from .env file
const bodyParser = require("body-parser"); // Middleware to parse request bodies
const express = require("express"); // Express web application framework
const ejs = require("ejs"); // Templating engine for rendering views
const mongoose = require("mongoose"); // MongoDB object modeling tool
const session = require("express-session"); // Middleware for session management
const LocalStrategy = require("passport-local").Strategy; // Strategy for authenticating with a username and password
const passport = require("passport"); // Passport authentication middleware
const passportLocalMongoose = require("passport-local-mongoose"); // Mongoose plugin for Passport
const GoogleStrategy = require("passport-google-oauth20").Strategy; // Strategy for authenticating with Google OAuth
const findOrCreate = require("mongoose-findorcreate"); // Mongoose plugin to find or create documents
const FacebookStrategy = require("passport-facebook").Strategy; // Strategy for authenticating with Facebook

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

userSchema.plugin(passportLocalMongoose); // Adds methods for registering and authenticating users
userSchema.plugin(findOrCreate); // Adds method to find or create documents

// Configure middleware for serving static files and setting view engine
app.use(express.static("public")); // Serve static files from the public directory
app.set("view engine", "ejs"); // Set EJS as the template engine
app.use(bodyParser.urlencoded({ extended: true })); // Parse URL-encoded bodies

// Set up session management for Passport
app.use(
  session({
    secret: "Our little Secret.", // Secret key for session encryption
    resave: false,
    saveUninitialized: false,
  })
);

// Initialize Passport and its session handling
app.use(passport.initialize()); // Initialize Passport
app.use(passport.session()); // Persist login sessions

// Create User model based on the defined schema
const User = new mongoose.model("User", userSchema);

// Configures Passport to use a local strategy for authentication
passport.use(new LocalStrategy(User.authenticate())); // Use local strategy for authentication

// Serialize and deserialize user instances to and from the session
passport.serializeUser(function (user, done) {
  done(null, user._id); // Store user ID in session
});

passport.deserializeUser(function (id, done) {
  User.findById(id) // Find user by ID
    .then((user) => {
      done(null, user); // Callback with user object
    })
    .catch(done); // Handle errors
});

// Define routes for the application
app.get("/", function (req, res) {
  res.render("home"); // Render home page
});

app.get("/login", function (req, res) {
  res.render("login"); // Render login page
});

app.get("/register", function (req, res) {
  res.render("register"); // Render registration page
});

app.get("/secrets", function (req, res) {
  User.find({ secret: { $ne: null } }) // Find users with secrets
    .then((foundUsers) => {
      if (foundUsers) {
        res.render("secrets", { usersWithSecrets: foundUsers }); // Render secrets page with users who have secrets
      }
    })
    .catch((err) => {
      console.log(err);
    });
});

app.get("/submit", (req, res) => {
  if (req.isAuthenticated()) {
    // Check if user is authenticated
    res.render("submit"); // Render submit page
  } else {
    res.redirect("login"); // Redirect to login if not authenticated
  }
});

// Handle user logout
app.get("/logout", function (req, res) {
  req.logout((err) => {
    // Log out the user
    if (err) {
      console.log(err);
    }
  });
  res.redirect("/"); // Redirect to home page
});

// Passport Google OAuth routes
app.get("/auth/google", function (req, res) {
  passport.authenticate("google", { scope: ["profile"] })(req, res); // Initiate Google OAuth authentication
});

app.get(
  "/auth/google/secrets",
  passport.authenticate("google", { failureRedirect: "/login" }),
  function (req, res) {
    // Successful authentication, redirect to secrets page
    res.redirect("/secrets");
  }
);

// Passport Facebook OAuth routes
app.get("/auth/facebook", passport.authenticate("facebook")); // Initiate Facebook OAuth authentication

app.get(
  "/auth/facebook/callback",
  passport.authenticate("facebook", { failureRedirect: "/login" }),
  function (req, res) {
    // Successful authentication, redirect to secrets page
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
        res.redirect("register"); // Redirect back to registration page on error
      } else {
        // Authenticate the newly registered user
        passport.authenticate("local")(req, res, function () {
          res.redirect("/secrets"); // Redirect to secrets page after successful registration
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

// Handle user submission of a secret
app.post("/submit", (req, res) => {
  const submittedSecret = req.body.secret;

  console.log(req.user.id);

  User.findById(req.user.id)
    .then((foundUser) => {
      if (foundUser) {
        foundUser.secret = submittedSecret;
        console.log(foundUser);
        return foundUser.save();
      }
    })
    .then(() => {
      res.redirect("/secrets");
    })
    .catch((err) => {
      console.log(err);
    });
});

// Start the server
app.listen(3000, function () {
  console.log("Server started on port 3000: http://localhost:3000/");
});
