
const express = require("express");
const bcrypt = require("bcrypt");
const db = require("../database");
const authMiddleware = require("../middleware/authMiddleware");
const allowRoles = require("../middleware/roleMiddleware");

const router = express.Router();

// Confirm that role ID 1 is the administrator role in your database.
router.use(authMiddleware, allowRoles(1));

// GET: View all admin accounts (never return password hashes)
router.get("/", async (req, res) => {
    try {
        const [admins] = await db.execute(`
            SELECT id, name, username, user_type_id
            FROM admin
            ORDER BY id DESC
        `);

        res.json({ success: true, admins });
    } catch (error) {
        console.error("Fetch admins failed:", error.message);
        res.status(500).json({
            success: false,
            message: "Failed to fetch admin accounts."
        });
    }
});

// POST: Create a new admin account
router.post("/", async (req, res) => {
    try {
        const { name, username, password, user_type_id } = req.body;

        if (
            typeof name !== "string" || !name.trim() ||
            typeof username !== "string" || !username.trim() ||
            typeof password !== "string" || password.length < 12 ||
            !Number.isInteger(Number(user_type_id))
        ) {
            return res.status(400).json({
                success: false,
                message: "Provide a name, username, password of at least 12 characters, and valid user_type_id."
            });
        }

        const [existing] = await db.execute(
            "SELECT id FROM admin WHERE username = ?",
            [username.trim()]
        );

        if (existing.length > 0) {
            return res.status(409).json({
                success: false,
                message: "Username already exists."
            });
        }

        const hashedPassword = await bcrypt.hash(password, 10);

        const [result] = await db.execute(
            `INSERT INTO admin (name, username, password, user_type_id)
             VALUES (?, ?, ?, ?)`,
            [
                name.trim(),
                username.trim(),
                hashedPassword,
                Number(user_type_id)
            ]
        );

        res.status(201).json({
            success: true,
            message: "Admin account created.",
            admin: {
                id: result.insertId,
                name: name.trim(),
                username: username.trim(),
                user_type_id: Number(user_type_id)
            }
        });
    } catch (error) {
        console.error("Create admin failed:", error.message);
        res.status(500).json({
            success: false,
            message: "Failed to create admin account."
        });
    }
});

// PUT: Update an admin's name and username
router.put("/:id", async (req, res) => {
    try {
        const id = Number(req.params.id);
        const { name, username } = req.body;

        if (
            !Number.isInteger(id) || id < 1 ||
            typeof name !== "string" || !name.trim() ||
            typeof username !== "string" || !username.trim()
        ) {
            return res.status(400).json({
                success: false,
                message: "Provide a valid ID, name, and username."
            });
        }

        const [result] = await db.execute(
            "UPDATE admin SET name = ?, username = ? WHERE id = ?",
            [name.trim(), username.trim(), id]
        );

        if (result.affectedRows === 0) {
            const [rows] = await db.execute(
                "SELECT id FROM admin WHERE id = ?",
                [id]
            );

            if (rows.length === 0) {
                return res.status(404).json({
                    success: false,
                    message: "Admin account not found."
                });
            }
        }

        res.json({
            success: true,
            message: "Admin details updated."
        });
    } catch (error) {
        if (error.code === "ER_DUP_ENTRY") {
            return res.status(409).json({
                success: false,
                message: "That username is already in use."
            });
        }

        console.error("Update admin failed:", error.message);
        res.status(500).json({
            success: false,
            message: "Failed to update admin account."
        });
    }
});

// PATCH: Deactivate an admin account
// This assumes your admin table has an `is_active` column.
router.patch("/:id/deactivate", async (req, res) => {
    try {
        const id = Number(req.params.id);

        if (!Number.isInteger(id) || id < 1) {
            return res.status(400).json({
                success: false,
                message: "Invalid admin ID."
            });
        }

        if (id === Number(req.user.id)) {
            return res.status(400).json({
                success: false,
                message: "You cannot deactivate your own account."
            });
        }

        const [result] = await db.execute(
            "UPDATE admin SET is_active = 0 WHERE id = ?",
            [id]
        );

        if (result.affectedRows === 0) {
            return res.status(404).json({
                success: false,
                message: "Admin account not found or already inactive."
            });
        }

        res.json({
            success: true,
            message: "Admin account deactivated."
        });
    } catch (error) {
        console.error("Deactivate admin failed:", error.message);
        res.status(500).json({
            success: false,
            message: "Deactivation failed. Verify that the is_active column exists."
        });
    }
});

/* Change the logged-in admin's own password */
router.patch("/:id/password", async (req, res) => {
  try {
    const id = Number(req.params.id);
    const { currentPassword, newPassword } = req.body;

    // Only allow changing your own password
    if (id !== Number(req.user.id)) {
      return res.status(403).json({
        success: false,
        message: "You can only change your own password."
      });
    }

    if (
      typeof currentPassword !== "string" ||
      typeof newPassword !== "string" ||
      newPassword.length < 12
    ) {
      return res.status(400).json({
        success: false,
        message: "Provide your current password and a new password of at least 12 characters."
      });
    }

    const [admins] = await db.execute(
      "SELECT id, password, is_active FROM admin WHERE id = ?",
      [id]
    );

    if (
      admins.length === 0 ||
      Number(admins[0].is_active) !== 1
    ) {
      return res.status(401).json({
        success: false,
        message: "Account is inactive or does not exist."
      });
    }

    const validPassword = await bcrypt.compare(
      currentPassword,
      admins[0].password
    );

    if (!validPassword) {
      return res.status(401).json({
        success: false,
        message: "Current password is incorrect."
      });
    }

    const hashedPassword = await bcrypt.hash(newPassword, 10);

    await db.execute(
      "UPDATE admin SET password = ? WHERE id = ?",
      [hashedPassword, id]
    );

    return res.json({
      success: true,
      message: "Password changed successfully."
    });
  } catch (error) {
    console.error("Change password failed:", error.message);

    return res.status(500).json({
      success: false,
      message: "Failed to change password."
    });
  }
});

module.exports = router;
