
const jwt = require("jsonwebtoken");
const db = require("../database");

const authMiddleware = async (req, res, next) => {
  try {
    const authHeader = req.headers.authorization;

    if (!authHeader || !authHeader.startsWith("Bearer ")) {
      return res.status(401).json({
        success: false,
        message: "Access token is required."
      });
    }

    const token = authHeader.split(" ")[1];

    const decoded = jwt.verify(token, process.env.JWT_SECRET);

    // Check the admin's current status in MySQL
    const [admins] = await db.execute(
      `SELECT id, username, user_type_id, is_active
       FROM admin
       WHERE id = ?`,
      [decoded.id]
    );

    if (admins.length === 0 || Number(admins[0].is_active) !== 1) {
      return res.status(401).json({
        success: false,
        message: "Account is inactive or does not exist."
      });
    }

    // Use current database details, not potentially outdated token roles
    req.user = {
      id: admins[0].id,
      username: admins[0].username,
      user_type_id: admins[0].user_type_id
    };

    next();
  } catch (error) {
    if (
      error.name === "JsonWebTokenError" ||
      error.name === "TokenExpiredError"
    ) {
      return res.status(401).json({
        success: false,
        message: "Invalid or expired token."
      });
    }

    console.error("Authentication error:", error.message);

    return res.status(500).json({
      success: false,
      message: "Authentication failed."
    });
  }
};

module.exports = authMiddleware;
