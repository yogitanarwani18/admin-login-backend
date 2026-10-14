
const express = require("express");
const authMiddleware = require("../middleware/authMiddleware");
const allowRoles = require("../middleware/roleMiddleware");

const router = express.Router();

// Replace 1 with the verified administrator role ID from your database.
const ADMIN_ROLE_ID = 1;

router.get(
    "/dashboard",
    authMiddleware,
    allowRoles(ADMIN_ROLE_ID),
    (req, res) => {
        res.json({
            success: true,
            message: "Welcome to the admin dashboard!",
            admin: {
                id: req.user.id,
                username: req.user.username,
                user_type_id: req.user.user_type_id
            }
        });
    }
);

module.exports = router;
