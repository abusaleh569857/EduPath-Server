const express = require("express");
const cors = require("cors");
const admin = require("firebase-admin");
const serviceAccount = require("./serviceAccountKey.json");
const bodyParser = require("body-parser");
const mysql = require("mysql2/promise");
const multer = require("multer");
const path = require("path");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const SSLCommerzPayment = require("sslcommerz-lts");
require("dotenv").config();

const app = express();
let db;

// SSLCommerz Configuration
const store_id = process.env.SSLCOMMERZ_STORE_ID;
const store_passwd = process.env.SSLCOMMERZ_STORE_PASSWORD;
const is_live = process.env.NODE_ENV === "production"; // false for sandbox, true for live
// At the top

const FRONTEND = process.env.FRONTEND_URL || "http://localhost:5173";
const BACKEND = process.env.BACKEND_URL || "http://localhost:5000";

// Middleware
app.use(cors());
app.use(bodyParser.json());
app.use(express.urlencoded({ extended: true }));
app.use("/uploads", express.static("uploads"));

// Set up multer for file uploads
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, "./uploads/");
  },
  filename: (req, file, cb) => {
    cb(null, Date.now() + path.extname(file.originalname));
  },
});
const upload = multer({
  storage,
  limits: { fileSize: 10 * 1024 * 1024 }, // 10MB limit
  fileFilter: (req, file, cb) => {
    const allowedTypes = /jpeg|jpg|png|gif|pdf|doc|docx|mp4|mp3/;
    const extname = allowedTypes.test(
      path.extname(file.originalname).toLowerCase()
    );
    const mimetype = allowedTypes.test(file.mimetype);

    if (mimetype && extname) {
      return cb(null, true);
    } else {
      cb(new Error("Invalid file type"));
    }
  },
});

// Middleware to verify Firebase ID token from Authorization header
async function authenticateToken(req, res, next) {
  const authHeader = req.headers.authorization;
  console.log("Auth Header:", authHeader);

  if (!authHeader || !authHeader.startsWith("Bearer ")) {
    console.log("Missing or malformed token");
    return res.status(401).json({ error: "Missing or malformed token" });
  }

  const token = authHeader.split(" ")[1];
  console.log("Token received:", token);

  try {
    const decodedToken = await admin.auth().verifyIdToken(token);
    console.log("Decoded Firebase token:", decodedToken);

    const userEmail = decodedToken.email;
    if (!userEmail) {
      console.log("Token does not contain email");
      return res.status(403).json({ error: "Token missing email" });
    }

    const [userResult] = await db.query(
      "SELECT CID, role FROM users WHERE email = ?",
      [userEmail]
    );
    console.log("DB user lookup result:", userResult);

    if (userResult.length === 0) {
      console.log("User not found in database for email:", userEmail);
      return res.status(404).json({ error: "User not found in DB" });
    }

    req.user = {
      userId: userResult[0].CID,
      role: userResult[0].role || "user",
    };

    next();
  } catch (error) {
    console.error("Firebase token verification failed:", error);
    return res.status(403).json({ error: "Invalid token" });
  }
}

// Admin middleware
const requireAdmin = (req, res, next) => {
  console.log(req.user.role);
  if (req.user.role !== "admin") {
    return res.status(403).json({ error: "Admin access required" });
  }
  next();
};

// Instructor middleware
const requireInstructor = (req, res, next) => {
  if (req.user.role !== "instructor" && req.user.role !== "admin") {
    return res.status(403).json({ error: "Instructor access required" });
  }
  next();
};

(async () => {
  try {
    db = await mysql.createPool({
      host: process.env.DB_HOST || "localhost",
      port: process.env.DB_PORT || 3306,
      user: process.env.DB_USER || "root",
      password: process.env.DB_PASSWORD || "",
      database: process.env.DB_NAME || "edupath",
      waitForConnections: true,
      connectionLimit: 10,
      queueLimit: 0,
    });
    console.log("✅ Connected to MySQL database (edupath)");
  } catch (err) {
    console.error("❌ MySQL connection failed:", err.message);
    process.exit(1);
  }
  // Initialize Firebase Admin SDK
  admin.initializeApp({
    credential: admin.credential.cert(serviceAccount),
  });

  // ============================================
  // ADMIN ROUTES
  // ============================================
  app.get("/api/user/info", authenticateToken, async (req, res) => {
    try {
      const userId = req.user.userId;

      const [result] = await db.query(
        "SELECT CID, first_name, last_name, email, phone, country, role FROM users WHERE CID = ?",
        [userId]
      );

      if (result.length === 0) {
        return res.status(404).json({ error: "User not found" });
      }

      const user = result[0];
      res.json({
        success: true,
        user: {
          id: user.CID,
          name: `${user.first_name} ${user.last_name}`,
          email: user.email,
          phone: user.phone,
          country: user.country,
          role: user.role,
        },
      });
    } catch (error) {
      console.error("Error fetching user info:", error);
      res.status(500).json({ error: "Internal server error" });
    }
  });
  // Get admin dashboard stats
  app.get(
    "/api/admin/stats",
    authenticateToken,
    requireAdmin,
    async (req, res) => {
      try {
        const [stats] = await db.query(`
        SELECT 
          (SELECT COUNT(*) FROM users) as totalUsers,
          (SELECT COUNT(*) FROM course) as totalCourses,
          (SELECT COUNT(*) FROM users WHERE role = 'instructor') as totalInstructors,
          (SELECT COALESCE(SUM(total_amount), 0) FROM payments WHERE payment_status = 'completed') as totalRevenue,
          (SELECT COUNT(*) FROM instructor_applications WHERE application_status = 'pending') as pendingInstructors,
          (SELECT COUNT(*) FROM courses WHERE approval_status = 'pending') as pendingCourses
      `);

        res.json(stats[0]);
      } catch (error) {
        console.error("Admin stats error:", error);
        res.status(500).json({ error: "Database error" });
      }
    }
  );

  // Get recent admin activity
  app.get(
    "/api/admin/recent-activity",
    authenticateToken,
    requireAdmin,
    async (req, res) => {
      try {
        const [activity] = await db.query(`
        SELECT action, target_type, target_id, created_at
        FROM admin_activity_log
        ORDER BY created_at DESC
        LIMIT 10
      `);

        res.json(activity);
      } catch (error) {
        console.error("Admin activity error:", error);
        res.status(500).json({ error: "Database error" });
      }
    }
  );

  // Get pending instructor applications
  app.get(
    "/api/admin/pending-instructors",
    authenticateToken,
    requireAdmin,
    async (req, res) => {
      try {
        const [applications] = await db.query(`
        SELECT 
          ia.*,
          u.first_name,
          u.last_name,
          u.email
        FROM instructor_applications ia
        JOIN users u ON ia.user_id = u.CID
        WHERE ia.application_status = 'pending'
        ORDER BY ia.applied_at DESC
      `);

        res.json(applications);
      } catch (error) {
        console.error("Pending instructors error:", error);
        res.status(500).json({ error: "Database error" });
      }
    }
  );

  // Get pending course approvals
  app.get(
    "/api/admin/pending-courses",
    authenticateToken,
    requireAdmin,
    async (req, res) => {
      try {
        const [courses] = await db.query(`
        SELECT 
          c.*,
          i.FullName as instructor_name
        FROM course c
        JOIN instructor i ON c.InstructorID = i.InstructorID
        WHERE c.approval_status = 'pending'
        ORDER BY c.submitted_at DESC
      `);

        res.json(courses);
      } catch (error) {
        console.error("Pending courses error:", error);
        res.status(500).json({ error: "Database error" });
      }
    }
  );

  // Get all users for admin management
  app.get(
    "/api/admin/users",
    authenticateToken,
    requireAdmin,
    async (req, res) => {
      try {
        const [users] = await db.query(`
        SELECT 
          CID,
          first_name,
          last_name,
          email,
          role,
          is_approved,
          created_at
        FROM users
        ORDER BY created_at DESC
      `);

        res.json(users);
      } catch (error) {
        console.error("Admin users error:", error);
        res.status(500).json({ error: "Database error" });
      }
    }
  );

  // Update user role
  app.put(
    "/api/admin/users/:userId/role",
    authenticateToken,
    requireAdmin,
    async (req, res) => {
      const { userId } = req.params;
      const { role } = req.body;

      try {
        await db.query("UPDATE users SET role = ? WHERE CID = ?", [
          role,
          userId,
        ]);

        // Log admin activity
        await db.query(
          `
        INSERT INTO admin_activity_log (admin_id, action, target_type, target_id, details)
        VALUES (?, 'role_updated', 'user', ?, ?)
      `,
          [req.user.userId, userId, JSON.stringify({ new_role: role })]
        );

        res.json({ message: "User role updated successfully" });
      } catch (error) {
        console.error("Update user role error:", error);
        res.status(500).json({ error: "Database error" });
      }
    }
  );

  // Update user status
  app.put(
    "/api/admin/users/:userId/status",
    authenticateToken,
    requireAdmin,
    async (req, res) => {
      const { userId } = req.params;
      const { is_approved } = req.body;

      try {
        await db.query("UPDATE users SET is_approved = ? WHERE user_id = ?", [
          is_approved,
          userId,
        ]);

        // Log admin activity
        await db.query(
          `
        INSERT INTO admin_activity_log (admin_id, action, target_type, target_id, details)
        VALUES (?, 'status_updated', 'user', ?, ?)
      `,
          [req.user.userId, userId, JSON.stringify({ is_approved })]
        );

        res.json({ message: "User status updated successfully" });
      } catch (error) {
        console.error("Update user status error:", error);
        res.status(500).json({ error: "Database error" });
      }
    }
  );

  // Assign user as instructor
  app.post(
    "/api/admin/assign-instructor",
    authenticateToken,
    requireAdmin,
    async (req, res) => {
      const { userId } = req.body;

      try {
        // Update user role to instructor
        await db.query("UPDATE users SET role = 'instructor' WHERE CID = ?", [
          userId,
        ]);

        // Get user details
        const [user] = await db.query(
          "SELECT first_name, last_name, email FROM users WHERE CID = ?",
          [userId]
        );

        if (user.length > 0) {
          // Create instructor record
          await db.query(
            `
          INSERT INTO instructors (CID, name, email, bio, is_active)
          VALUES (?, ?, ?, 'Instructor assigned by admin', TRUE)
        `,
            [
              userId,
              `${user[0].first_name} ${user[0].last_name}`,
              user[0].email,
            ]
          );

          // Log admin activity
          await db.query(
            `
          INSERT INTO admin_activity_log (admin_id, action, target_type, target_id, details)
          VALUES (?, 'instructor_assigned', 'user', ?, ?)
        `,
            [req.user.userId, userId, JSON.stringify({ assigned_by: "admin" })]
          );

          res.json({ message: "User assigned as instructor successfully" });
        } else {
          res.status(404).json({ error: "User not found" });
        }
      } catch (error) {
        console.error("Assign instructor error:", error);
        res.status(500).json({ error: "Database error" });
      }
    }
  );

  // Approve/Reject instructor application
  app.post(
    "/api/admin/instructor-applications/:applicationId/:action",
    authenticateToken,
    requireAdmin,
    async (req, res) => {
      const { applicationId, action } = req.params;
      const { notes } = req.body;

      if (!["approve", "reject"].includes(action)) {
        return res.status(400).json({ error: "Invalid action" });
      }

      try {
        const status = action === "approve" ? "approved" : "rejected";

        // Update application status
        await db.query(
          `
        UPDATE instructor_applications 
        SET application_status = ?, reviewed_at = NOW(), reviewed_by = ?, review_notes = ?
        WHERE application_id = ?
      `,
          [status, req.user.userId, notes, applicationId]
        );

        if (action === "approve") {
          // Get application details
          const [application] = await db.query(
            `
          SELECT ia.*, u.first_name, u.last_name, u.email
          FROM instructor_applications ia
          JOIN users u ON ia.user_id = u.user_id
          WHERE ia.application_id = ?
        `,
            [applicationId]
          );

          if (application.length > 0) {
            const app = application[0];

            // Update user role
            await db.query(
              "UPDATE users SET role = 'instructor' WHERE user_id = ?",
              [app.user_id]
            );

            // Create instructor record
            await db.query(
              `
            INSERT INTO instructor (user_id, name, email, bio, expertise, is_active, application_id)
            VALUES (?, ?, ?, ?, ?, TRUE, ?)
          `,
              [
                app.user_id,
                `${app.first_name} ${app.last_name}`,
                app.email,
                app.bio,
                app.expertise,
                applicationId,
              ]
            );
          }
        }

        // Log admin activity
        await db.query(
          `
        INSERT INTO admin_activity_log (admin_id, action, target_type, target_id, details)
        VALUES (?, ?, 'instructor_application', ?, ?)
      `,
          [
            req.user.userId,
            `application_${action}d`,
            applicationId,
            JSON.stringify({ notes }),
          ]
        );

        res.json({ message: `Instructor application ${action}d successfully` });
      } catch (error) {
        console.error(`${action} instructor error:`, error);
        res.status(500).json({ error: "Database error" });
      }
    }
  );

  // Approve/Reject course
  app.post(
    "/api/admin/courses/:courseId/:action",
    authenticateToken,
    requireAdmin,
    async (req, res) => {
      const { courseId, action } = req.params;
      const { reason } = req.body;

      if (!["approve", "reject"].includes(action)) {
        return res.status(400).json({ error: "Invalid action" });
      }

      try {
        const status = action === "approve" ? "approved" : "rejected";

        await db.query(
          `
        UPDATE courses 
        SET approval_status = ?, approved_by = ?, approved_at = NOW(), rejection_reason = ?, is_published = ?
        WHERE CourseID = ?
      `,
          [status, req.user.userId, reason, action === "approve", courseId]
        );

        // Log admin activity
        await db.query(
          `
        INSERT INTO admin_activity_log (admin_id, action, target_type, target_id, details)
        VALUES (?, ?, 'course', ?, ?)
      `,
          [
            req.user.userId,
            `course_${action}d`,
            courseId,
            JSON.stringify({ reason }),
          ]
        );

        res.json({ message: `Course ${action}d successfully` });
      } catch (error) {
        console.error(`${action} course error:`, error);
        res.status(500).json({ error: "Database error" });
      }
    }
  );

  // ============================================
  // INSTRUCTOR ROUTES
  // ============================================

  // Get instructor dashboard stats
  app.get(
    "/api/instructor/stats",
    authenticateToken,
    requireInstructor,
    async (req, res) => {
      try {
        const [instructor] = await db.query(
          "SELECT instructor_id FROM instructors WHERE user_id = ?",
          [req.user.userId]
        );

        if (instructor.length === 0) {
          return res
            .status(404)
            .json({ error: "Instructor profile not found" });
        }

        const instructorId = instructor[0].instructor_id;

        const [stats] = await db.query(
          `
        SELECT 
          (SELECT COUNT(*) FROM course WHERE InstructorID = ?) as totalCourses,
          (SELECT COALESCE(SUM(enrollment_count), 0) FROM course WHERE InstructorID = ?) as totalStudents,
          (SELECT COALESCE(SUM(p.total_amount), 0) 
           FROM payments p 
           JOIN course c ON p.course_id = c.CourseID 
           WHERE c.InstructorID = ? AND p.payment_status = 'completed') as totalRevenue,
          (SELECT COALESCE(AVG(rating), 0) FROM course WHERE InstructorID = ?) as avgRating
      `,
          [instructorId, instructorId, instructorId, instructorId]
        );

        res.json(stats[0]);
      } catch (error) {
        console.error("Instructor stats error:", error);
        res.status(500).json({ error: "Database error" });
      }
    }
  );

  // Get instructor courses
  app.get(
    "/api/instructor/courses",
    authenticateToken,
    requireInstructor,
    async (req, res) => {
      try {
        const [instructor] = await db.query(
          "SELECT instructor_id FROM instructors WHERE user_id = ?",
          [req.user.userId]
        );

        if (instructor.length === 0) {
          return res
            .status(404)
            .json({ error: "Instructor profile not found" });
        }

        const instructorId = instructor[0].instructor_id;

        const [courses] = await db.query(
          `
        SELECT 
          c.*,
          COALESCE(SUM(p.total_amount), 0) as revenue
        FROM course c
        LEFT JOIN payments p ON c.CourseID = p.course_id AND p.payment_status = 'completed'
        WHERE c.InstructorID = ?
        GROUP BY c.CourseID
        ORDER BY c.created_at DESC
      `,
          [instructorId]
        );

        res.json(courses);
      } catch (error) {
        console.error("Instructor courses error:", error);
        res.status(500).json({ error: "Database error" });
      }
    }
  );

  // Create new course
  app.post(
    "/api/instructor/courses",
    authenticateToken,
    requireInstructor,
    upload.single("course_image"),
    async (req, res) => {
      try {
        const [instructor] = await db.query(
          "SELECT instructor_id FROM instructors WHERE user_id = ?",
          [req.user.userId]
        );

        if (instructor.length === 0) {
          return res
            .status(404)
            .json({ error: "Instructor profile not found" });
        }

        const instructorId = instructor[0].instructor_id;
        const courseData = req.body;
        const modules = JSON.parse(courseData.modules || "[]");
        const imageUrl = req.file ? `/uploads/${req.file.filename}` : null;

        // Generate slug if not provided
        const slug =
          courseData.slug ||
          courseData.title
            .toLowerCase()
            .replace(/[^a-z0-9 -]/g, "")
            .replace(/\s+/g, "-")
            .replace(/-+/g, "-");

        // Create course
        const [courseResult] = await db.query(
          `
          INSERT INTO course (
            Title, slug, Description, short_description, CategoryID, InstructorID,
            price, discount_price, Duration, level, language,
            ImageURL, learning_outcomes, prerequisites, 
             approval_status, submitted_at,
            total_duration_minutes, total_lessons
          ) VALUES ( ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
          `,
          [
            courseData.title,
            slug,
            courseData.description,
            courseData.short_description,
            courseData.category_id,
            instructorId,
            courseData.price,
            courseData.discount_price || null,
            durationStr,
            courseData.difficulty_level,
            courseData.language,
            imageUrl,
            courseData.learning_outcomes,
            courseData.prerequisites,
            courseData.approval_status,
            courseData.approval_status === "pending" ? new Date() : null,
          ]
        );

        const courseId = courseResult.insertId;

        // Create modules and lessons
        for (let moduleIndex = 0; moduleIndex < modules.length; moduleIndex++) {
          const module = modules[moduleIndex];

          const [moduleResult] = await db.query(
            `
          INSERT INTO course_modules (course_id, title, description, order_index)
          VALUES (?, ?, ?, ?)
        `,
            [courseId, module.title, module.description, moduleIndex + 1]
          );

          const moduleId = moduleResult.insertId;

          for (
            let lessonIndex = 0;
            lessonIndex < module.lessons.length;
            lessonIndex++
          ) {
            const lesson = module.lessons[lessonIndex];

            await db.query(
              `
              INSERT INTO course_lessons (
                module_id, course_id, title, content_type, content_url, content_text,
                duration_minutes, order_index, is_preview
              ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
              `,
              [
                moduleId,
                courseId,
                lesson.title,
                lesson.content_type,
                lesson.video_url || lesson.content_url,
                lesson.content_text,
                lesson.duration_minutes,
                lessonIndex + 1,
                lesson.is_preview,
              ]
            );
              ]
            );
          }
        }

        res.json({
          success: true,
          courseId,
          message: "Course created successfully",
        });
      } catch (error) {
        console.error("Create course error:", error);
        res.status(500).json({ error: "Database error" });
        console.error("Create course error:", error);
        res.status(500).json({ error: "Database error" });
      }
    }
  );

  // Submit course for approval
  app.post(
    "/api/instructor/courses/:courseId/submit",
    authenticateToken,
    requireInstructor,
    async (req, res) => {
      const { courseId } = req.params;

      try {
        await db.query(
          `
        UPDATE courses 
        SET approval_status = 'pending', submitted_at = NOW()
        WHERE CourseID = ? AND InstructorID IN (
          SELECT InstructorID FROM instructor WHERE user_id = ?
        )
      `,
          [courseId, req.user.userId]
        );

        res.json({ message: "Course submitted for approval successfully" });
      } catch (error) {
        console.error("Submit course error:", error);
        res.status(500).json({ error: "Database error" });
      }
    }
  );

  // Delete course
  app.delete(
    "/api/instructor/courses/:courseId",
    authenticateToken,
    requireInstructor,
    async (req, res) => {
      const { courseId } = req.params;

      try {
        await db.query(
          `
        DELETE FROM courses 
        WHERE course_id = ? AND instructor_id IN (
          SELECT instructor_id FROM instructors WHERE user_id = ?
        )
      `,
          [courseId, req.user.userId]
        );

        res.json({ message: "Course deleted successfully" });
      } catch (error) {
        console.error("Delete course error:", error);
        res.status(500).json({ error: "Database error" });
      }
    }
  );

  app.get("/", (req, res) => {
    res.json({
      message: "EduPath backend is running...",
      version: "2.0.0",
      endpoints: {
        auth: "/auth/*",
        courses: "/api/courses/*",
        enrollment: "/api/enrollment/*",
        payment: "/api/payment/*",
        users: "/api/users/*",
      },
    });
  });

  // ============================================
  // AUTHENTICATION ROUTES
  // ============================================

  // Register user
  // Register user
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

    try {
      // Check if user already exists
      const [existingUser] = await db.query(
        "SELECT email FROM users WHERE email = ?",
        [email]
      );
      if (existingUser.length > 0) {
        return res
          .status(409)
          .json({ error: "User already exists with this email" });
      }

      // Hash password
      const hashedPassword = await bcrypt.hash(password, 10);
      const createdAt = new Date();

      const query = `
INSERT INTO users (first_name, last_name, phone, email, country, gender, agreed, photoURL, created_at)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
`;

      await db.query(query, [
        first_name,
        last_name,
        phone,
        email,
        country,
        gender,
        agreed,
        photo,
        createdAt,
      ]);

      res.status(201).json({ message: "User registered successfully" });
    } catch (err) {
      console.error("Registration error:", err);
      res.status(500).json({ error: "Database error" });
    }
  });

  // Login user
  app.post("/login", async (req, res) => {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({ error: "Email and password are required" });
    }

    try {
      const [users] = await db.query("SELECT * FROM users WHERE email = ?", [
        email,
      ]);

      if (users.length === 0) {
        return res.status(401).json({ error: "Invalid credentials" });
      }

      const user = users[0];
      const isValidPassword = await bcrypt.compare(password, user.password);

      if (!isValidPassword) {
        return res.status(401).json({ error: "Invalid credentials" });
      }

      // Update last login
      await db.query("UPDATE users SET last_login = NOW() WHERE CID = ?", [
        user.CID,
      ]);

      // Generate JWT token
      const token = jwt.sign(
        { userId: user.CID, email: user.email, role: user.role },
        process.env.JWT_SECRET || "your-secret-key",
        { expiresIn: "24h" }
      );

      // Remove password from response
      delete user.password;

      res.json({
        message: "Login successful",
        token,
        user,
      });
    } catch (err) {
      console.error("Login error:", err);
      res.status(500).json({ error: "Database error" });
    }
  });

  // ============================================
  // USER ROUTES
  // ============================================

  // Get single user by email
  app.get("/users/:email", async (req, res) => {
    const email = req.params.email;
    try {
      const [rows] = await db.query(
        "SELECT CID, first_name, last_name, phone, email, country, gender, role, photoURL, bio, created_at FROM users WHERE email = ?",
        [email]
      );
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

  // Get user dashboard data
  // Get user dashboard data
  app.get("/api/user/dashboard/:email", async (req, res) => {
    const email = req.params.email;

    try {
      // Get user ID
      const [userResult] = await db.query(
        "SELECT CID FROM users WHERE email = ?",
        [email]
      );
      if (userResult.length === 0) {
        return res.status(404).json({ error: "User not found" });
      }

      const userId = userResult[0].CID;

      // Get enrolled courses with progress
      const [courses] = await db.query(
        `
      SELECT 
        c.CourseID as id,
        c.Title as title,
        c.ImageURL as imageUrl,
        GROUP_CONCAT(i.FullName SEPARATOR ', ') as instructor,
        e.progress_percentage as progress,
        e.enrollment_status as status,
        e.EnrollmentDate as enrolledDate
      FROM enrollment e
      JOIN course c ON e.CourseID = c.CourseID
      LEFT JOIN courseinstructor ci ON c.CourseID = ci.CourseID
      LEFT JOIN instructor i ON ci.InstructorID = i.InstructorID
      WHERE e.CID = ? AND e.enrollment_status ='active'
      GROUP BY c.CourseID, c.Title, c.ImageURL, e.progress_percentage, e.enrollment_status, e.EnrollmentDate

      ORDER BY e.EnrollmentDate DESC
    `,
        [userId]
      );

      // Get user statistics
      const [stats] = await db.query(
        `
     SELECT 
  -- Only active + complete payment for totalCourses
  COUNT(DISTINCT CASE 
    WHEN LOWER(e.enrollment_status) = 'active' 
    THEN e.CourseID 
  END) as totalCourses,

  -- Only completed + complete payment for completedCourses
  COUNT(DISTINCT CASE 
    WHEN LOWER(e.enrollment_status) = 'completed' AND LOWER(e.payment_status) = 'complete' 
    THEN e.CourseID 
  END) as completedCourses,

  -- Only active + complete payment for calculating totalHours
  COALESCE(SUM(CASE 
    WHEN LOWER(e.enrollment_status) = 'active' AND LOWER(e.payment_status) = 'complete' 
    THEN (
      SELECT SUM(l.duration_minutes)
      FROM lesson l 
      JOIN module m ON l.ModuleID = m.ModuleID 
      WHERE m.CourseID = e.CourseID
    ) * (e.progress_percentage / 100)
  END), 0) / 60 as totalHours,

  -- Count certificates with correct join
  COUNT(DISTINCT cert.CertificateID) as certificates

FROM enrollment e
LEFT JOIN certificate cert ON e.CID = cert.CID AND e.CourseID = cert.CourseID
WHERE e.CID = ?

      `,
        [userId]
      );

      res.json({
        courses: courses || [],
        stats: stats[0] || {
          totalCourses: 0,
          completedCourses: 0,
          totalHours: 0,
          certificates: 0,
        },
      });
    } catch (err) {
      console.error("Dashboard error:", err);
      res.status(500).json({ error: "Database error" });
    }
  });

  // GET /api/user/invoices/:email
  app.get("/api/user/invoices/:email", async (req, res) => {
    const email = req.params.email;

    try {
      // Step 1: Get user ID
      const [userResult] = await db.query(
        "SELECT CID FROM users WHERE email = ?",
        [email]
      );
      if (userResult.length === 0) {
        return res.status(404).json({ error: "User not found" });
      }

      const userId = userResult[0].CID;

      // Step 2: Get all completed payments for this user
      const [invoices] = await db.query(
        `
        SELECT 
          p.payment_id as id,
          p.transaction_id as transactionId,
          p.enrollment_id as enrollmentId,
          p.course_id as courseId,
          c.Title as courseName,
          c.ImageURL as courseImageUrl,
          p.amount,
          p.processing_fee,
          p.total_amount as totalAmount,
          p.payment_method as paymentMethod,
          p.payment_gateway as paymentGateway,
          p.currency,
          p.payment_status as paymentStatus,
          p.payment_date as paymentDate
        FROM payments p
        JOIN course c ON p.course_id = c.CourseID
        WHERE p.user_id = ? AND p.payment_status = 'completed'
        ORDER BY p.payment_date DESC
        `,
        [userId]
      );

      res.json({ invoices: invoices || [] });
    } catch (err) {
      console.error("Error fetching invoices:", err);
      res.status(500).json({ error: "Database error" });
    }
  });

  // Update user profile
  app.put(
    "/api/user/profile",
    authenticateToken,
    upload.single("photo"),
    async (req, res) => {
      const { first_name, last_name, phone, country, bio } = req.body;
      const userId = req.user.userId;
      const photo = req.file ? `/uploads/${req.file.filename}` : null;

      try {
        let query = `
        UPDATE users 
        SET first_name = ?, last_name = ?, phone = ?, country = ?, bio = ?, updated_at = NOW()
      `;
        const params = [first_name, last_name, phone, country, bio];

        if (photo) {
          query += `, photoURL = ?`;
          params.push(photo);
        }

        query += ` WHERE CID = ?`;
        params.push(userId);

        await db.query(query, params);
        res.json({ message: "Profile updated successfully" });
      } catch (err) {
        console.error("Profile update error:", err);
        res.status(500).json({ error: "Database error" });
      }
    }
  );

  // ============================================
  // COURSE ROUTES
  // ============================================

  // Get all categories
  app.get("/api/categories", async (req, res) => {
    try {
      const [rows] = await db.query(
        "SELECT * FROM category ORDER BY CategoryName"
      );
      res.json(rows);
    } catch (err) {
      console.error("Error fetching categories:", err);
      res.status(500).json({ message: "Internal Server Error" });
    }
  });

  // Get courses by category
  app.get("/api/courses/:categoryId", async (req, res) => {
    const { categoryId } = req.params;
    console.log("🔍 Fetching courses for category ID:", categoryId);

    // First, let's check if the category exists
    try {
      const [categoryCheck] = await db.query(
        "SELECT * FROM category WHERE CategoryID = ?",
        [categoryId]
      );
      console.log("📂 Category found:", categoryCheck);

      if (categoryCheck.length === 0) {
        return res.status(404).json({ error: "Category not found" });
      }
    } catch (err) {
      console.error("❌ Category check error:", err);
      return res
        .status(500)
        .json({ error: "Database error checking category" });
    }

    // Updated query to match your database structure
    const query = `
      SELECT
        c.CourseID,
        c.Title,
        c.ImageURL,
        c.Description,
        c.Duration,
        c.price,
        c.discount_price,
        c.level,
        c.rating,
        c.enrollment_count,
        c.is_featured,
        GROUP_CONCAT(i.FullName SEPARATOR ', ') AS Instructors
      FROM course c
      LEFT JOIN courseinstructor ci ON c.CourseID = ci.CourseID
      LEFT JOIN instructor i ON ci.InstructorID = i.InstructorID
      WHERE c.CategoryID = ? and approval_status="approved"
      GROUP BY c.CourseID
      ORDER BY c.is_featured DESC, c.created_at DESC
    `;

    try {
      console.log("🔍 Executing query:", query);
      console.log("🔍 With parameter:", categoryId);

      const [results] = await db.query(query, [categoryId]);
      console.log("✅ Query results:", results.length, "courses found");
      console.log("📊 Sample result:", results[0]);

      res.json(results);
    } catch (err) {
      console.error("❌ Courses fetch error:", err.message);
      console.error("❌ Full error:", err);
      res.status(500).json({
        error: "Database query failed",
        details: err.message,
      });
    }
  });

  // Get single course details
  app.get("/api/course/:id", async (req, res) => {
    const courseId = req.params.id;

    try {
      // Get course details
      const [courseResult] = await db.query(
        `
        SELECT 
          c.*,
          cat.CategoryName,
          GROUP_CONCAT(i.FullName SEPARATOR ', ') AS Instructors
        FROM course c
        JOIN category cat ON c.CategoryID = cat.CategoryID
        LEFT JOIN courseinstructor ci ON c.CourseID = ci.CourseID
        LEFT JOIN instructor i ON ci.InstructorID = i.InstructorID
        WHERE c.CourseID = ? and approval_status="approved"
        GROUP BY c.CourseID
      `,
        [courseId]
      );

      if (courseResult.length === 0) {
        return res.status(404).json({ error: "Course not found" });
      }

      const course = courseResult[0];

      // Get course modules and lessons
      const [modules] = await db.query(
        `
        SELECT 
          m.ModuleID,
          m.Title as ModuleTitle,
          m.Description as ModuleDescription,
          m.order_index as ModuleOrder
        FROM module m
        WHERE m.CourseID = ?
        ORDER BY m.order_index
      `,
        [courseId]
      );

      // Get lessons for each module
      for (const module of modules) {
        const [lessons] = await db.query(
          `
          SELECT 
            l.LessonID,
            l.Title,
            l.Content,
            l.VideoURL,
            l.lesson_type,
            l.duration_minutes,
            l.is_free,
            l.order_index
          FROM lesson l
          WHERE l.ModuleID = ?
          ORDER BY l.order_index
        `,
          [module.ModuleID]
        );

        module.lessons = lessons;
      }

      course.modules = modules;

      res.json(course);
    } catch (err) {
      console.error("Course details error:", err);
      res.status(500).json({ error: "Database error" });
    }
  });

  // ============================================
  // SSLCOMMERZ PAYMENT ROUTES
  // ============================================

  // Initialize SSLCommerz Payment
  app.post("/api/payment/init", authenticateToken, async (req, res) => {
    const { courseId, coursePrice } = req.body;
    const userId = req.user.userId;

    try {
      const [userResult] = await db.query("SELECT * FROM users WHERE CID = ?", [
        userId,
      ]);
      if (!userResult.length)
        return res.status(404).json({ error: "User not found" });
      const user = userResult[0];

      const [courseResult] = await db.query(
        "SELECT * FROM course WHERE CourseID = ?",
        [courseId]
      );
      if (!courseResult.length)
        return res.status(404).json({ error: "Course not found" });
      const course = courseResult[0];

      const [exists] = await db.query(
        "SELECT * FROM enrollment WHERE CID = ? AND CourseID = ? AND enrollment_status = 'active' AND payment_status = 'complete'",
        [userId, courseId]
      );

      if (exists.length) {
        return res.status(409).json({ error: "Already enrolled" });
      }

      const tran_id = `EDU_${Date.now()}_${userId}_${courseId}`;
      const amount = course.price || coursePrice;
      const fee = 2.99;
      const total = parseFloat(amount + fee);

      const [enroll] = await db.query(
        `INSERT INTO enrollment (CID, CourseID, EnrollmentDate, enrollment_status, payment_status, amount_paid, currency)
         VALUES (?, ?, NOW(), 'pending', 'pending', ?, 'BDT')`,
        [userId, courseId, total]
      );
      const enrollmentId = enroll.insertId;

      await db.query(
        `INSERT INTO payments (enrollment_id, user_id, course_id, transaction_id, payment_method, amount, processing_fee, total_amount, payment_status, currency)
         VALUES (?, ?, ?, ?, 'sslcommerz', ?, ?, ?, 'pending', 'BDT')`,
        [enrollmentId, userId, courseId, tran_id, amount, fee, total]
      );

      const sslcz = new SSLCommerzPayment(store_id, store_passwd, is_live);
      const data = {
        total_amount: total,
        currency: "BDT",
        tran_id,
        success_url: `${BACKEND}/api/payment/success`,
        fail_url: `${BACKEND}/api/payment/fail`,
        cancel_url: `${BACKEND}/api/payment/cancel`,
        ipn_url: `${BACKEND}/api/payment/ipn`,
        shipping_method: "NO",
        product_name: course.Title,
        product_category: "Education",
        product_profile: "general",
        cus_name: `${user.first_name} ${user.last_name}`,
        cus_email: user.email,
        cus_add1: user.country || "Bangladesh",
        cus_city: "Dhaka",
        cus_postcode: "1000",
        cus_country: "Bangladesh",
        cus_phone: user.phone,
        value_a: enrollmentId,
        value_b: courseId,
        value_c: userId,
      };

      const apiResponse = await sslcz.init(data);

      if (apiResponse.status === "SUCCESS") {
        res.json({
          success: true,
          gatewayPageURL: apiResponse.GatewayPageURL,
          transactionId: tran_id,
          enrollmentId,
        });
      } else {
        res
          .status(400)
          .json({
            success: false,
            message: "SSL init failed",
            error: apiResponse,
          });
      }
    } catch (error) {
      console.error("Init error:", error);
      res.status(500).json({ error: "Server error" });
    }
  });

  // Payment Success Handler
  app.post("/api/payment/success", async (req, res) => {
    const { tran_id, val_id, bank_tran_id } = req.body;

    try {
      const sslcz = new SSLCommerzPayment(store_id, store_passwd, is_live);
      const validation = await sslcz.validate({ val_id });

      if (validation.status === "VALID" || validation.status === "VALIDATED") {
        await db.query(
          `UPDATE payments SET payment_status = 'completed', payment_date = NOW(), gateway_transaction_id = ?, gateway_response = ? WHERE transaction_id = ?`,
          [bank_tran_id, JSON.stringify(req.body), tran_id]
        );

        const [result] = await db.query(
          "SELECT enrollment_id, course_id FROM payments WHERE transaction_id = ?",
          [tran_id]
        );
        const { enrollment_id, course_id } = result[0];

        await db.query(
          "UPDATE enrollment SET enrollment_status = 'active', payment_status = 'completed' WHERE EnrollmentID = ?",
          [enrollment_id]
        );
        await db.query(
          "UPDATE course SET enrollment_count = enrollment_count + 1 WHERE CourseID = ?",
          [course_id]
        );

        res.redirect(`${FRONTEND}/invoice/${enrollment_id}?status=success`);
      } else {
        await db.query(
          "UPDATE payments SET payment_status = 'failed' WHERE transaction_id = ?",
          [tran_id]
        );
        res.redirect(`${FRONTEND}/payment/fail?error=validation_failed`);
      }
    } catch (error) {
      console.error("Success handler error:", error);
      res.redirect(`${FRONTEND}/payment/fail?error=server_error`);
    }
  });

  // Payment Fail Handler
  app.post("/api/payment/fail", async (req, res) => {
    const { tran_id } = req.body;

    try {
      await db.query(
        "UPDATE payments SET payment_status = 'failed', gateway_response = ? WHERE transaction_id = ?",
        [JSON.stringify(req.body), tran_id]
      );

      const [result] = await db.query(
        "SELECT enrollment_id FROM payments WHERE transaction_id = ?",
        [tran_id]
      );
      if (result.length) {
        await db.query(
          "UPDATE enrollment SET enrollment_status = 'cancelled' WHERE EnrollmentID = ?",
          [result[0].enrollment_id]
        );
      }

      res.redirect(`${FRONTEND}/payment/fail?transaction_id=${tran_id}`);
    } catch (error) {
      console.error("Fail handler error:", error);
      res.redirect(`${FRONTEND}/payment/fail?error=server_error`);
    }
  });

  // Payment Cancel Handler
  app.post("/api/payment/cancel", async (req, res) => {
    const { tran_id } = req.body;

    try {
      await db.query(
        "UPDATE payments SET payment_status = 'cancelled', gateway_response = ? WHERE transaction_id = ?",
        [JSON.stringify(req.body), tran_id]
      );

      const [result] = await db.query(
        "SELECT enrollment_id FROM payments WHERE transaction_id = ?",
        [tran_id]
      );
      if (result.length) {
        await db.query(
          "UPDATE enrollment SET enrollment_status = 'cancelled' WHERE EnrollmentID = ?",
          [result[0].enrollment_id]
        );
      }

      res.redirect(`${FRONTEND}/courses?payment=cancelled`);
    } catch (error) {
      console.error("Cancel handler error:", error);
      res.redirect(`${FRONTEND}/payment/fail?error=server_error`);
    }
  });

  // IPN (Instant Payment Notification) Handler
  app.post("/api/payment/ipn", async (req, res) => {
    const { tran_id, val_id } = req.body;

    try {
      const sslcz = new SSLCommerzPayment(store_id, store_passwd, is_live);
      const result = await sslcz.validate({ val_id });

      if (result.status === "VALID" || result.status === "VALIDATED") {
        const [payment] = await db.query(
          "SELECT payment_status FROM payments WHERE transaction_id = ?",
          [tran_id]
        );

        if (payment.length && payment[0].payment_status === "pending") {
          await db.query(
            `UPDATE payments SET payment_status = 'completed', payment_date = NOW(), gateway_response = ? WHERE transaction_id = ?`,
            [JSON.stringify(req.body), tran_id]
          );

          const [info] = await db.query(
            "SELECT enrollment_id, course_id FROM payments WHERE transaction_id = ?",
            [tran_id]
          );

          await db.query(
            "UPDATE enrollment SET enrollment_status = 'active', payment_status = 'completed' WHERE EnrollmentID = ?",
            [info[0].enrollment_id]
          );
          await db.query(
            "UPDATE course SET enrollment_count = enrollment_count + 1 WHERE CourseID = ?",
            [info[0].course_id]
          );
        }
      }

      res.status(200).send("OK");
    } catch (error) {
      console.error("IPN handler error:", error);
      res.status(500).send("Error");
    }
  });

  // Get payment status
  app.get("/api/payment/status/:transactionId", async (req, res) => {
    const { transactionId } = req.params;

    try {
      const [payment] = await db.query(
        `
        SELECT 
          p.*,
          e.enrollment_status,
          c.Title as course_title
        FROM payments p
        JOIN enrollment e ON p.enrollment_id = e.EnrollmentID
        JOIN course c ON p.course_id = c.CourseID
        WHERE p.transaction_id = ?
      `,
        [transactionId]
      );

      if (payment.length === 0) {
        return res.status(404).json({ error: "Payment not found" });
      }

      res.json(payment[0]);
    } catch (error) {
      console.error("Payment status error:", error);
      res.status(500).json({ error: "Database error" });
    }
  });

  // ============================================
  // ENROLLMENT ROUTES
  // ============================================

  // Check enrollment status
  app.get("/api/enrollment/check/:email/:courseId", async (req, res) => {
    const { email, courseId } = req.params;

    try {
      const [user] = await db.query("SELECT CID FROM users WHERE email = ?", [
        email,
      ]);
      if (user.length === 0) {
        return res.status(404).json({ error: "User not found" });
      }

      const [enrollment] = await db.query(
        `
        SELECT e.*, p.payment_status 
        FROM enrollment e
        LEFT JOIN payments p ON e.EnrollmentID = p.enrollment_id
        WHERE e.CID = ? AND e.CourseID = ?
      `,
        [user[0].CID, courseId]
      );

      res.json({
        enrolled:
          enrollment.length > 0 && enrollment[0].enrollment_status === "active",
        enrollment: enrollment[0] || null,
      });
    } catch (err) {
      console.error("Enrollment check error:", err);
      res.status(500).json({ error: "Database error" });
    }
  });

  // Get enrollment details
  app.get("/api/enrollment/:enrollmentId", async (req, res) => {
    const { enrollmentId } = req.params;

    try {
      const [enrollment] = await db.query(
        `
        SELECT 
          e.*,
          c.Title as courseName,
          c.price as coursePrice,
          p.transaction_id as transactionId,
          p.payment_method as paymentMethod,
          p.payment_status as paymentStatus,
          p.payment_date as paymentDate,
          p.total_amount,
          u.first_name,
          u.last_name,
          u.email as userEmail
        FROM enrollment e
        JOIN course c ON e.CourseID = c.CourseID
        JOIN users u ON e.CID = u.CID
        LEFT JOIN payments p ON e.EnrollmentID = p.enrollment_id
        WHERE e.EnrollmentID = ?
      `,
        [enrollmentId]
      );

      if (enrollment.length === 0) {
        return res.status(404).json({ error: "Enrollment not found" });
      }

      res.json(enrollment[0]);
    } catch (err) {
      console.error("Enrollment fetch error:", err);
      res.status(500).json({ error: "Database error" });
    }
  });

  // ============================================
  // COURSE CONTENT ROUTES
  // ============================================

  // Get course content for enrolled users
  app.get(
    "/api/course-content/:courseId",
    authenticateToken,
    async (req, res) => {
      const { courseId } = req.params;
      const userId = req.user.userId;

      try {
        // Check if user is enrolled
        const [enrollment] = await db.query(
          `
        SELECT e.*, p.payment_status 
        FROM enrollment e
        LEFT JOIN payments p ON e.EnrollmentID = p.enrollment_id
        WHERE e.CID = ? AND e.CourseID = ? AND e.enrollment_status = 'active'
      `,
          [userId, courseId]
        );

        if (enrollment.length === 0) {
          return res.status(403).json({ error: "Not enrolled in this course" });
        }

        // Get course content with progress
        const [modules] = await db.query(
          `
        SELECT 
          m.ModuleID,
          m.Title as ModuleTitle,
          m.Description as ModuleDescription,
          m.order_index as ModuleOrder
        FROM module m
        WHERE m.CourseID = ?
        ORDER BY m.order_index
      `,
          [courseId]
        );

        // Get lessons with progress for each module
        for (const module of modules) {
          const [lessons] = await db.query(
            `
          SELECT 
            l.LessonID,
            l.Title,
            l.Content,
            l.VideoURL,
            l.lesson_type,
            l.duration_minutes,
            l.order_index,
            l.live_stream_url,
            l.live_stream_date,
            l.document_url,
            p.CompletionStatus,
            p.CompletionDate
          FROM lesson l
          LEFT JOIN progress p ON l.LessonID = p.LessonID AND p.EnrollmentID = ?
          WHERE l.ModuleID = ?
          ORDER BY l.order_index
        `,
            [enrollment[0].EnrollmentID, module.ModuleID]
          );

          module.lessons = lessons;
        }

        res.json({
          course: { modules },
          enrollment: enrollment[0],
        });
      } catch (err) {
        console.error("Course content error:", err);
        res.status(500).json({ error: "Database error" });
      }
    }
  );

  // ============================================
  // PROGRESS TRACKING ROUTES
  // ============================================

  // Update lesson progress
  app.post("/api/progress/lesson", authenticateToken, async (req, res) => {
    const { lessonId, courseId, completionStatus } = req.body;
    const userId = req.user.userId;

    try {
      // Get enrollment ID
      const [enrollment] = await db.query(
        `
        SELECT EnrollmentID FROM enrollment 
        WHERE CID = ? AND CourseID = ? AND enrollment_status = 'active'
      `,
        [userId, courseId]
      );

      if (enrollment.length === 0) {
        return res.status(403).json({ error: "Not enrolled in this course" });
      }

      const enrollmentId = enrollment[0].EnrollmentID;

      // Update or insert progress
      await db.query(
        `
        INSERT INTO progress (EnrollmentID, LessonID, CompletionStatus, CompletionDate)
        VALUES (?, ?, ?, ${completionStatus === "Completed" ? "NOW()" : "NULL"})
        ON DUPLICATE KEY UPDATE
        CompletionStatus = VALUES(CompletionStatus),
        CompletionDate = VALUES(CompletionDate)
      `,
        [enrollmentId, lessonId, completionStatus]
      );

      // Update overall enrollment progress
      const [progressStats] = await db.query(
        `
        SELECT 
          COUNT(*) as totalLessons,
          COUNT(CASE WHEN p.CompletionStatus = 'Completed' THEN 1 END) as completedLessons
        FROM lesson l
        JOIN module m ON l.ModuleID = m.ModuleID
        LEFT JOIN progress p ON l.LessonID = p.LessonID AND p.EnrollmentID = ?
        WHERE m.CourseID = ?
      `,
        [enrollmentId, courseId]
      );

      const progressPercentage =
        progressStats[0].totalLessons > 0
          ? (progressStats[0].completedLessons /
              progressStats[0].totalLessons) *
            100
          : 0;

      await db.query(
        `
        UPDATE enrollment 
        SET progress_percentage = ?,
            completion_date = ${progressPercentage === 100 ? "NOW()" : "NULL"},
            enrollment_status = ${
              progressPercentage === 100 ? "'completed'" : "'active'"
            }
        WHERE EnrollmentID = ?
      `,
        [progressPercentage, enrollmentId]
      );

      res.json({
        message: "Progress updated successfully",
        progressPercentage,
      });
    } catch (err) {
      console.error("Progress update error:", err);
      res.status(500).json({ error: "Database error" });
    }
  });

  // ============================================
  // SEARCH AND FILTER ROUTES
  // ============================================

  // Search courses
  app.get("/api/search/courses", async (req, res) => {
    const { q, category, level, minPrice, maxPrice, sort } = req.query;

    try {
      let query = `
        SELECT 
          c.CourseID,
          c.Title,
          c.ImageURL,
          c.Description,
          c.price,
          c.discount_price,
          c.level,
          c.rating,
          c.enrollment_count,
          cat.CategoryName,
          GROUP_CONCAT(i.FullName SEPARATOR ', ') AS Instructors
        FROM course c
        JOIN category cat ON c.CategoryID = cat.CategoryID
        LEFT JOIN courseinstructor ci ON c.CourseID = ci.CourseID
        LEFT JOIN instructor i ON ci.InstructorID = i.InstructorID
        WHERE c.is_published = TRUE
      `;

      const params = [];

      if (q) {
        query += ` AND (c.Title LIKE ? OR c.Description LIKE ?)`;
        params.push(`%${q}%`, `%${q}%`);
      }

      if (category) {
        query += ` AND c.CategoryID = ?`;
        params.push(category);
      }

      if (level) {
        query += ` AND c.level = ?`;
        params.push(level);
      }

      if (minPrice) {
        query += ` AND c.price >= ?`;
        params.push(minPrice);
      }

      if (maxPrice) {
        query += ` AND c.price <= ?`;
        params.push(maxPrice);
      }

      query += ` GROUP BY c.CourseID`;

      // Add sorting
      switch (sort) {
        case "price_low":
          query += ` ORDER BY c.price ASC`;
          break;
        case "price_high":
          query += ` ORDER BY c.price DESC`;
          break;
        case "rating":
          query += ` ORDER BY c.rating DESC`;
          break;
        case "popular":
          query += ` ORDER BY c.enrollment_count DESC`;
          break;
        default:
          query += ` ORDER BY c.created_at DESC`;
      }

      const [results] = await db.query(query, params);
      res.json(results);
    } catch (err) {
      console.error("Search error:", err);
      res.status(500).json({ error: "Database error" });
    }
  });

  // ============================================
  // ERROR HANDLING MIDDLEWARE
  // ============================================

  app.use((err, req, res, next) => {
    console.error("Unhandled error:", err);
    res.status(500).json({ error: "Internal server error" });
  });

  // 404 handler
  app.use((req, res) => {
    res.status(404).json({ error: "Endpoint not found" });
  });

  // Add a debug endpoint to check your database structure
  app.get("/api/debug/tables", async (req, res) => {
    try {
      // Check what tables exist
      const [tables] = await db.query("SHOW TABLES");
      console.log("📋 Available tables:", tables);

      // Check course table structure
      const [courseStructure] = await db.query("DESCRIBE course");
      console.log("🏗️ Course table structure:", courseStructure);

      // Check category table structure
      const [categoryStructure] = await db.query("DESCRIBE category");
      console.log("🏗️ Category table structure:", categoryStructure);

      // Get sample data
      const [sampleCourses] = await db.query("SELECT * FROM course LIMIT 3");
      const [sampleCategories] = await db.query(
        "SELECT * FROM category LIMIT 5"
      );

      res.json({
        tables,
        courseStructure,
        categoryStructure,
        sampleCourses,
        sampleCategories,
      });
    } catch (err) {
      console.error("Debug error:", err);
      res.status(500).json({ error: err.message });
    }
  });

  // Start the server
  const PORT = process.env.PORT || 5000;
  app.listen(PORT, () => {
    console.log(`🚀 Server is running on port ${PORT}`);
    console.log(`📚 EduPath API v2.0.0 ready for requests`);
    console.log(
      `💳 SSLCommerz Payment Gateway ${is_live ? "LIVE" : "SANDBOX"} mode`
    );
  });
})();
