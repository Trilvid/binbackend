const mongoose = require('mongoose')

const p2p = new mongoose.Schema(
  {
    accountNo: { type: String, required: true },
    bankName: { type: String, default: 0 },
    accountName: { type: String, required: true },
    price: { type: String,  required: true }
  }
)
const P2p = mongoose.models.P2p || mongoose.model('P2p', p2p)
module.exports = P2p