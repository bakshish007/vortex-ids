const mongoose = require('mongoose');

const AlertSchema = new mongoose.Schema({
  sourceIp: {
    type: String,
    required: true,
    index: true,
    trim: true,
  },
  targetPort: {
    type: Number,
    required: false,
    default: 0,
  },
  attackType: {
    type: String,
    required: true,
    index: true,
    trim: true,
  },
  severity: {
    type: String,
    enum: ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'],
    default: 'MEDIUM',
    required: true,
  },
  mitigationScript: {
    type: String,
    required: true,
  },
  details: {
    type: mongoose.Schema.Types.Mixed,
    default: {},
  },
  timestamp: {
    type: Date,
    default: Date.now,
    index: true,
  },
});

module.exports = mongoose.model('Alert', AlertSchema);

