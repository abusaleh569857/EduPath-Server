const express = require("express");
const cors = require("cors");
const bodyParser = require("body-parser");
const mysql = require("mysql2/promise");
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

(async () => {
  let db;
  try {
    db = await mysql.createPool({
      host: process.env.DB_HOST,
      user: process.env.DB_USER,
      password: process.env.DB_PASSWORD,
      database: process.env.DB_NAME,
    });
    console.log(" Connected to MySQL database (edupath)");
  } catch (err) {
    console.error(" MySQL connection failed:", err.message);
    process.exit(1);
  }

  app.get("/", (req, res) => {
    res.send("EduPath backend is running...");
  });

  // app.use((req, res, next) => {
  //   console.log(`➡️ [${req.method}] ${req.url}`);
  //   next();
  // });

  // Get single user by email
  app.get("/users/:email", async (req, res) => {
    const email = req.params.email;
    try {
      const [rows] = await db.query("SELECT * FROM users WHERE email = ?", [
        email,
      ]);
      if (rows.length) {
        res.json(rows[0]);
      } else {
        res.status(404).json({ error: "User not found" });
      }
    } catch (err) {
      console.error("DB error:", err);
      res.status(500).json({ error: "Database error" });
    }
  });

  // GET all categories
  app.get("/api/categories", async (req, res) => {
    try {
      const [rows] = await db.query("SELECT * FROM Category");
      res.json(rows);
    } catch (err) {
      console.error("Error fetching categories:", err);
      res.status(500).json({ message: "Internal Server Error" });
    }
  });

  app.get("/api/courses/:categoryId", async (req, res) => {
    const { categoryId } = req.params;
    console.log("API CALL: /api/courses/:categoryId =>", categoryId);

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

    try {
      const [results] = await db.query(query, [categoryId]);
      console.log("✅ Courses returned:", results.length);
      res.json(results);
    } catch (err) {
      console.error("🔥 MySQL QUERY ERROR:", err.message);
      res.status(500).send("Database query failed.");
    }
  });

  //  Register user
  app.post("/register", upload.single("photo"), async (req, res) => {
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

    try {
      await db.query(query, [
        first_name,
        last_name,
        phone,
        email,
        password,
        country,
        gender,
        agreed,
        photo,
      ]);
      res.status(201).json({ message: "User registered successfully" });
    } catch (err) {
      console.error("Database error:", err);
      res.status(500).json({ error: "Database error" });
    }
  });

  // Get all users
  app.get("/users", async (req, res) => {
    try {
      const [results] = await db.query("SELECT * FROM users");
      res.json(results);
    } catch (err) {
      console.error("MySQL Query Error:", err);
      res.status(500).json({ error: "Database error" });
    }
  });

  // Start the server
  const PORT = process.env.PORT || 5000;
  app.listen(PORT, () => {
    console.log(` Server is running on port ${PORT}`);
  });
})();
