const mongoose = require('mongoose');

const TelemetrySchema = new mongoose.Schema({
  cpuUsage: {
    type: Number,
    required: true,
  },
  ramUsage: {
    type: Number,
    required: true,
  },
  timestamp: {
    type: Date,
    default: Date.now,
    index: true,
  },
});

module.exports = mongoose.model('Telemetry', TelemetrySchema);

