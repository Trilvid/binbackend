const mongoose = require('mongoose')

const loan = new mongoose.Schema(
  {
    loanAmount: { type: String, required: true },
    loanBalance: { type: Number, default: 0 },
    loanDesc: { type: String, required: true },
    status: { type: String, default:'pending' },
    user: {
        type: mongoose.Schema.ObjectId,
        ref: 'User',
        required: true
    }
  }
)
const Loan = mongoose.models.Loan || mongoose.model('Loan', loan)
module.exports = Loan