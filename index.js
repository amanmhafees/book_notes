import express from "express";
import bodyParser from "body-parser";
import pg from "pg";
import bcrypt from "bcrypt";
import passport from "passport";
import { Strategy as LocalStrategy } from "passport-local";
import { Strategy as GoogleStrategy } from "passport-google-oauth20";
import session from "express-session";
import env from "dotenv";

let currentUserId=0;

const app = express();
const port = 3000;
const saltRounds = 10;
env.config();

app.use(
  session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: true,
  })
);

app.use(passport.initialize());
app.use(passport.session());
app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static("public"));

const db = new pg.Client({
  user: process.env.PG_USER,
  host: process.env.PG_HOST,
  database: process.env.PG_DATABASE,
  password: process.env.PG_PASSWORD,
  port: process.env.PG_PORT,
});
db.connect();

app.get("/", (req, res) => {
  res.render("home.ejs");
});
app.get("/login", (req, res) => {
  res.render("login.ejs");
});
app.get("/register", (req, res) => {
  res.render("register.ejs");
});
app.get("/logout", (req, res) => {
  req.logout(function (err) {
    if (err) {
      return next(err);
    }
    res.redirect("/");
  });
});
app.get("/add", (req, res) => {
  res.render("add.ejs");
});

app.get("/books", (req, res) => {
  if (req.isAuthenticated()) {
    res.render("books.ejs");
  } else {
    res.redirect("/login");
  }
});
app.get(
  "/auth/google",
  passport.authenticate("google", {
    scope: ["profile", "email"],
  })
);

app.get(
  "/auth/google/books",
  passport.authenticate("google", {
    successRedirect: "/books",
    failureRedirect: "/login",
  })
);

app.post(
  "/login",
  passport.authenticate("local", {
    successRedirect: "/books",
    failureRedirect: "/login",
  })
);

app.post("/register", async (req, res) => {
  const email = req.body.username;
  const password = req.body.password;

  try {
    const checkResult = await db.query("SELECT * FROM users WHERE email = $1", [email]);

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
              currentUserId=result.rows[0];
              res.redirect("/books");
            }
          });
        }
      });
    }
  } catch (err) {
    console.log(err);
  }
});

app.post("/login", async (req, res) => {
  const email = req.body.username;
  const loginPassword = req.body.password;

  try {
    const result = await db.query("SELECT * FROM users WHERE email = $1", [
      email,
    ]);
    if (result.rows.length > 0) {
      const user = result.rows[0];
      const storedHashedPassword = user.password;
      bcrypt.compare(loginPassword, storedHashedPassword, (err, result) => {
        if (err) {
          console.error("Error comparing passwords:", err);
        } else {
          if (result) {
            res.render("books.ejs");
          } else {
            res.send("Incorrect Password");
          }
        }
      });
    } else {
      res.send("User not found");
    }
  } catch (err) {
    console.log(err);
  }
});

passport.use(
  new LocalStrategy(async function verify(username, password, cb) {
    try {
      const result = await db.query("SELECT * FROM users WHERE email = $1", [username]);
      if (result.rows.length > 0) {
        const user = result.rows[0];
        const storedHashedPassword = user.password;
        bcrypt.compare(password, storedHashedPassword, (err, valid) => {
          if (err) {
            console.error("Error comparing passwords:", err);
            return cb(err);
          }
          if (valid) {
            return cb(null, user);
          } else {
            return cb(null, false, { message: "Incorrect password." });
          }
        });
      } else {
        return cb(null, false, { message: "User not found." });
      }
    } catch (err) {
      return cb(err);
    }
  })
);

passport.serializeUser((user, done) => {
  done(null, user.id);
});

passport.deserializeUser(async (id, done) => {
  try {
    const result = await db.query("SELECT * FROM users WHERE id = $1", [id]);
    if (result.rows.length > 0) {
      done(null, result.rows[0]);
    } else {
      done(new Error("User not found"));
    }
  } catch (err) {
    done(err);
  }
});


async function submit(){
  const title=document.getElementById('bookTitle').textContent;
  const author=document.getElementById('author').textContent;
  const coverImage=document.getElementById('coverImage').src;
  const note=document.getElementById('bookNote').value;
  const userId=currentUserId;

  const result = await db.query("INSERT INTO notes (title, author, coverImage, note, userId) VALUES ($1, $2, $3, $4, $5)", [title, author, coverImage, note, userId]);
  res.redirect("/books");
}
const books=[];
app.get("/notes", async (req, res) => {
  if (req.isAuthenticated()) {
    try {
      const userId = req.user.id;
      const result = await db.query("SELECT * FROM notes WHERE userId = $1", [userId]);
      res.json(result.rows);
    } catch (err) {
      console.error("Error fetching notes:", err);
      res.status(500).send("Internal Server Error");
    }
  } else {
    res.redirect("/login");
  }
});
async function fetchUserNotes() {
  try {
      const response = await fetch('/notes');
      if (response.ok) {
          const notes = await response.json();
          displayNotes(notes);
      } else {
          console.error('Failed to fetch notes');
      }
  } catch (error) {
      console.error('Error fetching notes:', error);
  }
}

function displayNotes(notes) {
  const container = document.getElementById('notes-container');
  container.innerHTML = ''; // Clear previous content

  if (notes.length === 0) {
      container.innerHTML = '<p>No notes found.</p>';
      return;
  }

  notes.forEach(note => {
      const noteElement = document.createElement('div');
      noteElement.classList.add('note');

      noteElement.innerHTML = `
          <h2>${note.title}</h2>
          <p><strong>Author:</strong> ${note.author}</p>
          <img src="${note.coverimage}" alt="${note.title} Cover" style="max-width: 200px;">
          <p>${note.note}</p>
      `;

      container.appendChild(noteElement);
  });
}





app.listen(port, () => {
  console.log(`Server running on port ${port}`);
});