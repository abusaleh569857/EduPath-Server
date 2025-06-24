const express = require("express");
const cors = require("cors");
const bodyParser = require("body-parser");
const mysql = require("mysql2");
const multer = require("multer");
const path = require("path");
require("dotenv").config();

const app = express();

// Middleware
app.use(cors());
app.use(bodyParser.json());
app.use(express.urlencoded({ extended: true }));

// Set up multer for file uploads
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, "./uploads/");
  },
  filename: (req, file, cb) => {
    cb(null, Date.now() + path.extname(file.originalname));
  },
});
const upload = multer({ storage });

// Create MySQL connection
const db = mysql.createConnection({
  host: process.env.DB_HOST || "localhost",
  user: process.env.DB_USER || "root",
  password: process.env.DB_PASSWORD || "",
  database: process.env.DB_NAME || "edupath",
});

// Connect to database
db.connect((err) => {
  if (err) {
    console.error("❌ Database connection failed:", err.message);
    process.exit(1);
  } else {
    console.log("✅ Connected to MySQL database (edupath)");

    // All routes inside this block to ensure DB is connected
    app.get("/", (req, res) => {
      res.send("EduPath backend is running...");
    });

    app.get("/users/:email", (req, res) => {
      const email = req.params.email;
      db.query(
        "SELECT * FROM users WHERE email = ?",
        [email],
        (err, results) => {
          if (err) {
            console.error("DB error:", err);
            return res.status(500).json({ error: "Database error" });
          }
          if (results.length) {
            res.json(results[0]);
          } else {
            res.status(404).json({ error: "User not found" });
          }
        }
      );
    });

    app.get("/api/categories", (req, res) => {
      db.query("SELECT * FROM Category", (err, rows) => {
        if (err) {
          console.error("Error fetching categories:", err);
          return res.status(500).json({ message: "Internal Server Error" });
        }
        res.json(rows);
      });
    });

    app.get("/api/courses/:categoryId", (req, res) => {
      const { categoryId } = req.params;
      const query = `
        SELECT
          Course.CourseID,
          Course.Title,
          Course.ImageURL,
          Course.Description,
          Course.Duration,
          GROUP_CONCAT(Instructor.FullName SEPARATOR ', ') AS Instructors
        FROM Course
        LEFT JOIN CourseInstructor ON Course.CourseID = CourseInstructor.CourseID
        LEFT JOIN Instructor ON CourseInstructor.InstructorID = Instructor.InstructorID
        WHERE Course.CategoryID = ?
        GROUP BY Course.CourseID;
      `;

      db.query(query, [categoryId], (err, results) => {
        if (err) {
          console.error("🔥 MySQL QUERY ERROR:", err.message);
          return res.status(500).send("Database query failed.");
        }
        res.json(results);
      });
    });

    app.post("/register", upload.single("photo"), (req, res) => {
      const {
        first_name,
        last_name,
        phone,
        email,
        password,
        country,
        gender,
        agreed,
      } = req.body;
      const photo = req.file ? `/uploads/${req.file.filename}` : null;

      if (
        !first_name ||
        !last_name ||
        !phone ||
        !email ||
        !password ||
        !country ||
        !gender ||
        !agreed
      ) {
        return res.status(400).json({ error: "All fields are required" });
      }

      const query = `
        INSERT INTO users (first_name, last_name, phone, email, password, country, gender, agreed, photoURL)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
      `;

      db.query(
        query,
        [
          first_name,
          last_name,
          phone,
          email,
          password,
          country,
          gender,
          agreed,
          photo,
        ],
        (err) => {
          if (err) {
            console.error("Database error:", err);
            return res.status(500).json({ error: "Database error" });
          }
          res.status(201).json({ message: "User registered successfully" });
        }
      );
    });

    app.get("/users", (req, res) => {
      db.query("SELECT * FROM users", (err, results) => {
        if (err) {
          console.error("MySQL Query Error:", err);
          return res.status(500).json({ error: "Database error" });
        }
        res.json(results);
      });
    });

    // Start server after DB connected
    const PORT = process.env.PORT || 5000;
    app.listen(PORT, () => {
      console.log(`🚀 Server is running on port ${PORT}`);
    });
  }
});
