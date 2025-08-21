// utils/auditLogger.js
async function logAudit(conn, event_type, user_email, user_type, success, message) {
  try {
    await conn.execute(
      `INSERT INTO audit_logs (event_type, user_email, user_type, success, message, timestamp)
       VALUES (?, ?, ?, ?, ?, NOW())`,
      [event_type, user_email, user_type, success, message]
    );
  } catch (err) {
    console.error("Failed to log audit event:", err.message);
  }
}

module.exports = { logAudit };
