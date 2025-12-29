// // backend/models/User.js
// const mongoose = require("mongoose");
// const bcrypt = require("bcryptjs");

// const UserSchema = new mongoose.Schema({
//   name: { type: String, required: true, trim: true },
//   email: { type: String, required: true, unique: true, lowercase: true, trim: true },
//   password: { type: String, required: true },
//   role: { type: String, enum: ["elder", "family"], required: true }
// }, { timestamps: true });

// // Hash password before saving
// UserSchema.pre("save", async function (next) {
//   if (!this.isModified("password")) return next();
//   try {
//     const salt = await bcrypt.genSalt(10);
//     this.password = await bcrypt.hash(this.password, salt);
//     return next();
//   } catch (err) {
//     return next(err);
//   }
// });

// // helper to compare password
// UserSchema.methods.comparePassword = function (candidate) {
//   return bcrypt.compare(candidate, this.password);
// };

// module.exports = mongoose.model("User", UserSchema);
