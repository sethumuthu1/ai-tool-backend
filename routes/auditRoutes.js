const express = require('express');
const router = express.Router();
const db = require('../db');

// GET: Fetch audit logs
router.get('/', async (req, res) => {
  try {
    const [logs] = await db.execute('SELECT * FROM audit_logs ORDER BY created_at DESC LIMIT 100');
    res.json({ success: true, logs });
  } catch (err) {
    console.error('Error fetching logs:', err);
    res.status(500).json({ success: false, message: 'Failed to fetch audit logs' });
  }
});

module.exports = router;
