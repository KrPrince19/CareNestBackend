// backend/server.js
const express = require('express');
const mongoose = require("mongoose");
const cors = require('cors');
const bodyParser = require('body-parser');
const cron = require('node-cron');
const http = require('http');
const jwt = require('jsonwebtoken');
const { Server } = require("socket.io");
const bcrypt = require("bcryptjs");
const dotenv = require("dotenv")



// Models
const Medicine = require("./models/Medicines");

const app = express();
const JWT_SECRET = process.env.JWT_SECRET || "supersecretkey123";
const PORT = process.env.PORT || 5000;




// 
// Middleware
app.use(cors());
app.use(bodyParser.json());
dotenv.config();

// SOCKET.IO setup
const server = http.createServer(app);
const io = new Server(server, {
  cors: { origin: "*" }
});


// MongoDB Connection
console.log("Connecting to:", process.env.MONGO_URI);
mongoose.connect(process.env.MONGO_URI)

// mongoose.connect("mongodb://localhost:27017/carenest") //E4LuIwhKkTa9f6n7  pikachukr06_db_user
  .then(async () => {
    console.log("✅ MongoDB Connected");
    
    // ⚠️ CRITICAL FIX: Drop the old unique email index if it exists
    try {
      const collection = mongoose.connection.collection('users');
      if (await collection.indexExists('email_1')) {
        await collection.dropIndex('email_1');
        console.log("🔄 Old unique email restriction removed. Multi-role enabled.");
      }
    } catch (e) {
      // Index likely already removed
    }
  })
  .catch(err => console.error("❌ DB Error:", err));

// --- USER SCHEMA & AUTH ROUTES ---

const userSchema = new mongoose.Schema(
  {
    name: String,
    email: { type: String, required: true },
    password: String,
    role: { type: String, enum: ["family", "elder"], required: true },

    // 🔐 Security fields
    loginAttempts: { type: Number, default: 0 },
    lockUntil: { type: Date, default: null },
  },
  { timestamps: true }
);


// Compound Index: Ensures (Email + Role) is unique
userSchema.index({ email: 1, role: 1 }, { unique: true });

const User = mongoose.model("User", userSchema);

// 1. SIGNUP ROUTE
app.post("/signup", async (req, res) => {
  try {
    const { name, email, password, role } = req.body;
    const normalizedEmail = email.toLowerCase().trim();

    if (!name || !email || !password || !role) {
      return res.status(400).json({ error: "All fields are required" });
    }

    const existingUser = await User.findOne({ email: normalizedEmail, role });
    if (existingUser) {
      return res.status(409).json({ error: `An account with this email already exists for role: ${role}` });
    }


    const passwordRegex =
  /^(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&#]).{8,}$/;

if (!passwordRegex.test(password)) {
  return res.status(400).json({
    error: "Weak password format"
  });
}

    const hashedPassword = await bcrypt.hash(password, 10);

    const newUser = await User.create({
      name,
      email: normalizedEmail,
      password: hashedPassword,
      role,
    });

    const token = jwt.sign(
        { id: newUser._id, email: newUser.email, role: newUser.role }, 
        JWT_SECRET, 
        { expiresIn: "1h" }
    );

    return res.status(201).json({
      message: "Signup successful",
      token,
      user: { name: newUser.name, email: newUser.email, role: newUser.role },
    });
  } catch (err) {
    if (err.code === 11000) {
        return res.status(409).json({ error: `User already exists for role: ${req.body.role}` });
    }
    console.log("Signup Error:", err);
    res.status(500).json({ error: "Internal Server Error" });
  }
});

// 2. LOGIN ROUTE
app.post("/login", async (req, res) => {
  try {
    const { email, password, role } = req.body;

    if (!email || !password || !role) {
      return res.status(400).json({
        error: "Email, password & role required",
      });
    }

    const emailNormalized = email.trim().toLowerCase();
    const user = await User.findOne({ email: emailNormalized, role });

    if (!user) {
      return res.status(404).json({
        error: "User not found for the selected role",
      });
    }

    // 🔓 AUTO-UNLOCK if lock time expired
    if (user.lockUntil && user.lockUntil <= Date.now()) {
      user.loginAttempts = 0;
      user.lockUntil = null;
      await user.save();
    }

    // 🔒 STILL LOCKED
    if (user.lockUntil && user.lockUntil > Date.now()) {
      const minutesLeft = Math.ceil(
        (user.lockUntil - Date.now()) / (60 * 1000)
      );

      return res.status(403).json({
        error: `Too many failed attempts. Try again after ${minutesLeft} minutes.`,
      });
    }

    const validPass = await bcrypt.compare(password, user.password);

    // ❌ WRONG PASSWORD
    if (!validPass) {
      user.loginAttempts += 1;

      if (user.loginAttempts >= 3) {
        user.lockUntil = new Date(Date.now() + 15 * 60 * 1000); // 15 min lock
        await user.save();

        return res.status(403).json({
          error: "Too many failed attempts. Account locked for 15 minutes.",
        });
      }

      await user.save();
      return res.status(400).json({
        error: `Incorrect password. ${3 - user.loginAttempts} attempts left.`,
      });
    }

    // ✅ CORRECT PASSWORD → FULL RESET
    user.loginAttempts = 0;
    user.lockUntil = null;
    await user.save();

    const token = jwt.sign(
      { id: user._id, email: user.email, role: user.role },
      process.env.JWT_SECRET,
      { expiresIn: "1h" }
    );

    return res.status(200).json({
      message: "Login successful",
      token,
      user: {
        name: user.name,
        email: user.email,
        role: user.role,
      },
    });

  } catch (err) {
    console.error("Login Error:", err);
    res.status(500).json({ error: "Internal Server Error" });
  }
});



// ================= RESET PASSWORD (ROLE BASED) =================
app.post("/reset-password-direct", async (req, res) => {
  const { email, role, newPassword, confirmPassword } = req.body;

  try {
    if (!email || !role || !newPassword || !confirmPassword) {
      return res.status(400).json({ error: "All fields are required" });
    }

    if (newPassword !== confirmPassword) {
      return res.status(400).json({ error: "Passwords do not match" });
    }

    // ✅ Email + Role check
    const normalizedEmail = email.toLowerCase().trim();
    const user = await User.findOne({ email: normalizedEmail, role });
    if (!user) {
      return res.status(404).json({
        error: `No ${role} account found with this email`,
      });
    }

    const hashedPassword = await bcrypt.hash(newPassword, 10);
    user.password = hashedPassword;
    await user.save();

    res.json({ message: "Password successfully changed" });

  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Failed to reset password" });
  }
});


// ========== MEDICINE ROUTES ==========

app.get('/medicines', async (req, res) => {
  try {
    const { email } = req.query; 
    let query = {};
    if (email) {
        query = { userEmail: email };
    }
    const meds = await Medicine.find(query);
    res.status(200).json(meds);
  } catch (err) {
    res.status(500).json({ error: "Failed to fetch medicines" });
  }
});

app.post('/medicines', async (req, res) => {
  try {
    const { name, dose, time, forWhom, stock, userEmail } = req.body;
    
    if (!userEmail) {
        return res.status(400).json({ error: "User email is missing. Please log in again." });
    }

    const newMedicine = new Medicine({ 
        name, 
        dose, 
        time, 
        forWhom,
        status: 'upcoming',
        stock: stock || 0,
        userEmail: userEmail 
    });

    await newMedicine.save();
    io.emit('REFRESH_DATA'); 
    res.status(201).json(newMedicine);
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Failed to create medicine' });
  }
});

app.patch('/medicines/:id', async (req, res) => {
  try {
    const { status } = req.body;
    const medId = req.params.id;

    const currentMed = await Medicine.findById(medId);
    if (!currentMed) return res.status(404).json({ error: "Not found" });

    let updateFields = {
        status: status,
        takenAt: status === "taken" ? new Date() : null
    };

    if (status === 'taken' && currentMed.status !== 'taken') {
        if (currentMed.stock > 0) {
            await Medicine.findByIdAndUpdate(medId, { $inc: { stock: -1 } });
        }
    }

    const updated = await Medicine.findByIdAndUpdate(
      medId,
      updateFields,
      { new: true } 
    );

    io.emit("REFRESH_DATA");
    res.json(updated);
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: "Failed to update medicine" });
  }
});



// ========== DAILY RESET CRON JOB ==========
cron.schedule("0 0 * * *", async () => {
  try {
    await Medicine.updateMany({ status: "taken" }, { status: "upcoming", takenAt: null });
    io.emit("REFRESH_DATA");
    console.log("🔄 Daily medicine reset completed");
  } catch (err) {
    console.error("Cron Error:", err);
  }
}, { timezone: "Asia/Kolkata" });

// START SERVER
server.listen(PORT, () => {
  console.log(`🚀 Real-Time Server running on http://localhost:${PORT}`);
});