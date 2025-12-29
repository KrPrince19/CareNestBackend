const mongoose = require('mongoose');

const MedicineSchema = new mongoose.Schema({
  name: { type: String, required: true },
  dose: String,
  time: String,
  forWhom: String,
  status: { type: String, default: 'upcoming' },
  takenAt: Date,
  stock: { type: Number, default: 0 },
  // ✅ NEW FIELD: Link medicine to a specific user
  userEmail: { type: String, required: true } 
});

module.exports = mongoose.model('Medicines', MedicineSchema);