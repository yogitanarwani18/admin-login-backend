
const express = require("express");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const db = require("../database");

const router = express.Router();

router.post("/login", async (req, res) => {
    try {
        const { username, password } = req.body;

        if (
            typeof username !== "string" ||
            typeof password !== "string" ||
            !username.trim() ||
            !password
        ) {
            return res.status(400).json({
                success: false,
                message: "Username and password are required."
            });
        }

        const [admins] = await db.execute(
            `SELECT id, name, username, password, user_type_id, is_active
             FROM admin
             WHERE username = ?`,
            [username.trim()]
        );

        if (admins.length === 0) {
            console.log("Login failed: username not found.");
            return res.status(401).json({
                success: false,
                message: "Invalid username or password."
            });
        }

        const admin = admins[0];

        if (Number(admin.is_active) !== 1) {
            console.log("Login failed: account inactive.");
            return res.status(401).json({
                success: false,
                message: "Invalid username or password."
            });
        }

        const validPassword = await bcrypt.compare(
            password,
            admin.password
        );

        console.log("Password comparison result:", validPassword);

        if (!validPassword) {
            console.log("Login failed: password did not match.");
            return res.status(401).json({
                success: false,
                message: "Invalid username or password."
            });
        }

        if (!process.env.JWT_SECRET) {
            throw new Error("JWT_SECRET is missing from .env");
        }

        const token = jwt.sign(
            {
                id: admin.id,
                username: admin.username,
                user_type_id: admin.user_type_id
            },
            process.env.JWT_SECRET,
            { expiresIn: "1h" }
        );

        return res.status(200).json({
            success: true,
            message: "Login successful",
            token,
            admin: {
                id: admin.id,
                name: admin.name,
                username: admin.username,
                user_type_id: admin.user_type_id
            }
        });

    } catch (error) {
        console.error("Login error:", error.message);

        return res.status(500).json({
            success: false,
            message: "Internal server error."
        });
    }
});

module.exports = router;
