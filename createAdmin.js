
require("dotenv").config();

const bcrypt = require("bcrypt");
const db = require("./database");

async function createAdmin() {
    try {
        const [roles] = await db.execute(
            "SELECT id FROM user_types WHERE type_name = ?",
            ["Admin"]
        );

        if (roles.length === 0) {
            throw new Error(
                "Admin role not found in user_types table."
            );
        }

        const [existing] = await db.execute(
            "SELECT id FROM admin WHERE username = ?",
            ["admin01"]
        );

        if (existing.length > 0) {
            console.log("Admin account already exists.");
            return;
        }

        const password = "ChangeThisPassword123!";
        const hashedPassword = await bcrypt.hash(password, 12);

        await db.execute(
            `INSERT INTO admin
             (name, username, password, user_type_id)
             VALUES (?, ?, ?, ?)`,
            [
                "System Administrator",
                "admin01",
                hashedPassword,
                roles[0].id
            ]
        );

        console.log("Admin account created successfully.");
        console.log("Username: admin01");
        console.log("Use the password configured in createAdmin.js");
    } catch (error) {
    console.error("Error creating admin:", error);
    process.exitCode = 1;
    } finally {
        await db.end();
    }
}

createAdmin();
