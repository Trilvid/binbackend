const mongoose = require('mongoose')

const admin = new mongoose.Schema(
  {
    email: { type: String, required: true, unique: true, default: 'kultureassetsworldwide@gmail.com' },
    password: { type: String, required: true, default: 'pass1234' },
    role: {type: String, default: 'admin'}
  }
)
const Admin = mongoose.models.Admin || mongoose.model('Admin', admin)
module.exports = Admin