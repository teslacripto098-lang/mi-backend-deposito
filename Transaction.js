const mongoose = require('mongoose');

const transactionSchema = new mongoose.Schema({
    userId: { 
        type: String, 
        required: true 
    },
    type: { 
        type: String, 
        enum: ['DEPOSIT', 'WITHDRAWAL'], 
        default: 'DEPOSIT' 
    },
    amount: { 
        type: Number, 
        required: true 
    },
    uniqueWalletCode: { 
        type: String, 
        required: true, 
        unique: true 
    },
    status: { 
        type: String, 
        enum: ['PENDING', 'COMPLETED', 'FAILED'], 
        default: 'PENDING' 
    }
}, { timestamps: true });

module.exports = mongoose.model('Transaction', transactionSchema);
