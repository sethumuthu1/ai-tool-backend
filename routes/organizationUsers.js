const express = require("express");
const router = express.Router();
const db = require("../db"); // your DB instance
const authenticateToken = require("../middleware/authenticateToken");

router.get("/organization/users", authenticateToken, async (req, res) => {
  const userEmail = req.user.email;

  if (!req.user || req.user.userType !== "organization") {
    return res.status(403).json({ success: false, message: "Access denied" });
  }

  const userDomain = userEmail.split("@")[1];

  try {
    // Get current org user record to fetch their organization_domain
    const [orgResults] = await db.query(
      "SELECT organization_domain FROM organizations WHERE email = ?",
      [userEmail]
    );

    if (orgResults.length === 0) {
      return res.status(404).json({ success: false, message: "Organization user not found" });
    }

    const orgDomain = orgResults[0].organization_domain;

    // Fetch all normal users with:
    // - Email domain matching orgDomain
    // - OR organization field matching orgDomain (case-insensitive)
    const [users] = await db.query(
      `
      SELECT id, first_name, last_name, email, phone, organization
      FROM users
      WHERE 
        email LIKE ?
        OR LOWER(organization) = LOWER(?)
      `,
      [`%@${orgDomain}`, orgDomain]
    );

    return res.json({ success: true, users });
  } catch (err) {
    console.error("DB Error:", err);
    return res.status(500).json({ success: false, message: "Server error" });
  }
});

module.exports = router;
