import express from "express"; import bodyParser from "body-parser"; import pg from "pg"; import bcrypt from "bcrypt"; import passport from "passport"; import { Strategy as LocalStrategy } from "passport-local"; import { Strategy as GoogleStrategy } from "passport-google-oauth20"; import session from "express-session"; import env from "dotenv";

const app = express(); const port = 3000; const saltRounds = 10; env.config();

app.use( session({ secret: process.env.SESSION_SECRET, resave: false, saveUninitialized: true, }) );

app.use(passport.initialize()); app.use(passport.session()); app.use(bodyParser.urlencoded({ extended: true })); app.use(express.static("public"));

const db = new pg.Client({ user: process.env.PG_USER, host: process.env.PG_HOST, database: process.env.PG_DATABASE, password: process.env.PG_PASSWORD, port: process.env.PG_PORT, }); db.connect();

app.get("/", (req, res) => { res.render("home.ejs"); }); app.get("/login", (req, res) => { res.render("login.ejs"); }); app.get("/register", (req, res) => { res.render("register.ejs"); }); app.get("/logout", (req, res) => { req.logout(function (err) { if (err) { return next(err); } res.redirect("/"); }); });

app.get("/books", (req, res) => { if (req.isAuthenticated()) { res.render("books.ejs"); } else { res.redirect("/login"); } }); app.get( "/auth/google", passport.authenticate("google", { scope: ["profile", "email"], }) );

app.get( "/auth/google/books", passport.authenticate("google", { successRedirect: "/books", failureRedirect: "/login", }) );

app.post( "/login", passport.authenticate("local", { successRedirect: "/books", failureRedirect: "/login", }) );

app.post("/register", async (req, res) => { const email = req.body.username; const password = req.body.password;

try { const checkResult = await db.query("SELECT * FROM users WHERE email = $1", [email]);


  if (checkResult.rows.length > 0) {
    res.redirect("/login");
  } else {
    bcrypt.hash(password, saltRounds, async (err, hash) => {
      if (err) {
        console.error("Error hashing password:", err);
      } else {
        const result = await db.query(
          "INSERT INTO users (email, password) VALUES ($1, $2) RETURNING *",
          [email, hash]
        );
        const user = result.rows[0];
        req.login(user, (err) => {
          if (err) {
            console.error("Error logging in after registration:", err);
            res.redirect("/login");
          } else {
            res.redirect("/books");
          }
        });
      }
    });
  }
  } catch (err) { console.log(err); } });
  
  passport.use( new LocalStrategy(async function verify(username, password, cb) { try { const result = await db.query("SELECT * FROM users WHERE email = $1", [username]); if (result.rows.length > 0) { const user = result.rows[0]; const storedHashedPassword = user.password; bcrypt.compare(password, storedHashedPassword, (err, valid) => { if (err) { console.error("Error comparing passwords:", err); return cb(err); } if (valid) { return cb(null, user); } else { return cb(null, false, { message: "Incorrect password." }); } }); } else { return cb(null, false, { message: "User not found." }); } } catch (err) { return cb(err); } }) );
  
  passport.use( new GoogleStrategy( { clientID: process.env.GOOGLE_CLIENT_ID, clientSecret: process.env.GOOGLE_CLIENT_SECRET, callbackURL: "http://localhost:3000/auth/google/books", userProfileURL: "https://www.googleapis.com/oauth2/v3/userinfo", }, async (accessToken, refreshToken, profile, done) => { try { const email = profile.emails[0].value; const result = await db.query("SELECT * FROM users WHERE email = $1", [email]); if (result.rows.length === 0) { const newUser = await db.query( "INSERT INTO users (email, password) VALUES ($1, $2) RETURNING *", [email, "google"] ); return done(null, newUser.rows[0]); } else { return done(null, result.rows[0]); } } catch (err) { return done(err); } } ) );
  
  passport.serializeUser((user, done) => { done(null, user.id); });
  
  passport.deserializeUser(async (id, done) => { try { const result = await db.query("SELECT * FROM users WHERE id = $1", [id]); if (result.rows.length > 0) { done(null, result.rows[0]); } else { done(new Error("User not found")); } } catch (err) { done(err); } });
  
  app.listen(port, () => { console.log(`Server running on port ${port}`); });