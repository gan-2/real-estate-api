const express = require("express");
const cors = require("cors");
const sqlite3 = require("sqlite3").verbose();
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");

const app = express();
app.use(cors());
app.use(express.json());

// Secret key for JWT (in real apps, keep this in environment variable)
const JWT_SECRET = "supersecretkey";

// Database setup
const db = new sqlite3.Database("./realestate.db");

// Create tables if not exists
db.run(`CREATE TABLE IF NOT EXISTS properties (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  title TEXT,
  price REAL
)`);

db.run(`CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  username TEXT UNIQUE,
  password TEXT
)`);

// Middleware to check JWT
function authenticateToken(req, res, next) {
  const authHeader = req.headers["authorization"];
  const token = authHeader && authHeader.split(" ")[1]; // Expect: "Bearer <token>"

  if (!token) return res.status(401).json({ message: "No token provided" });

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ message: "Invalid token" });
    req.user = user;
    next();
  });
}

// Routes
app.get("/", (req, res) => res.send("Real Estate API Running 🚀"));

// ---- Properties ----
app.get("/properties", (req, res) => {
  db.all("SELECT * FROM properties", [], (err, rows) => {
    if (err) return res.status(500).send(err);
    res.json(rows);
  });
});

// Protected: only logged-in users can add properties
app.post("/properties", authenticateToken, (req, res) => {
  const { title, price } = req.body;
  db.run("INSERT INTO properties (title, price) VALUES (?, ?)", [title, price], function(err) {
    if (err) return res.status(500).send(err);
    res.json({ id: this.lastID, title, price });
  });
});

// ---- Users ----
// Register new user
app.post("/register", async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) return res.status(400).json({ message: "Username and password required" });

  const hashedPassword = await bcrypt.hash(password, 10);

  db.run("INSERT INTO users (username, password) VALUES (?, ?)", [username, hashedPassword], function(err) {
    if (err) {
      if (err.message.includes("UNIQUE")) {
        return res.status(400).json({ message: "Username already exists" });
      }
      return res.status(500).send(err);
    }
    res.json({ id: this.lastID, username });
  });
});

// Login user -> return JWT token
app.post("/login", (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) return res.status(400).json({ message: "Username and password required" });

  db.get("SELECT * FROM users WHERE username = ?", [username], async (err, user) => {
    if (err) return res.status(500).send(err);
    if (!user) return res.status(400).json({ message: "User not found" });

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) return res.status(400).json({ message: "Invalid password" });

    // Generate JWT token
    const token = jwt.sign({ id: user.id, username: user.username }, JWT_SECRET, { expiresIn: "1h" });
    res.json({ message: "Login successful", token });
  });
});

// Start server
app.listen(3000, () => console.log("API running on http://localhost:3000"));
