// Admin API — Dashboard operations (login, users, licenses, stats)
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const { v4: uuidv4 } = require("uuid");
const { getDb, initDb } = require("./_db");

const JWT_SECRET = process.env.JWT_SECRET || "zenith-super-secret-key-change-me";

// Helper: verify admin JWT
function verifyToken(req) {
  const auth = req.headers.authorization;
  if (!auth || !auth.startsWith("Bearer ")) return null;
  try {
    return jwt.verify(auth.split(" ")[1], JWT_SECRET);
  } catch {
    return null;
  }
}

module.exports = async function handler(req, res) {
  // Handle CORS preflight
  if (req.method === "OPTIONS") {
    return res.status(200).end();
  }

  try {
    await initDb();
    const sql = getDb();

    const action = req.query.action || req.body?.action;

    if (!action) {
      return res.status(400).json({ status: "error", message: "No action specified." });
    }

    // ─── ADMIN LOGIN ─────────────────────────────────────
    if (action === "login") {
      const { username, password } = req.body || {};

      if (!username || !password) {
        return res.status(400).json({ status: "error", message: "Faltan credenciales." });
      }

      // Check if owner account exists, create if not
      const ownerCheck = await sql`SELECT id FROM users WHERE username = 'owner'`;
      if (ownerCheck.length === 0) {
        const ownerHash = await bcrypt.hash("admin123", 10);
        await sql`INSERT INTO users (username, password, role) VALUES ('owner', ${ownerHash}, 'owner')`;
      }

      // Auto-fix owner password trick (same as original PHP)
      if (username === "owner" && password === "admin123") {
        const hash = await bcrypt.hash("admin123", 10);
        await sql`UPDATE users SET password = ${hash} WHERE username = 'owner'`;

        const token = jwt.sign({ username: "owner", role: "owner" }, JWT_SECRET, { expiresIn: "24h" });
        return res.json({ status: "success", token, role: "owner" });
      }

      const admins = await sql`SELECT * FROM users WHERE username = ${username} AND role IN ('owner', 'admin')`;
      const admin = admins[0];

      if (!admin || !(await bcrypt.compare(password, admin.password))) {
        return res.json({ status: "error", message: "Credenciales incorrectas o no eres administrador." });
      }

      const token = jwt.sign({ username: admin.username, role: admin.role }, JWT_SECRET, { expiresIn: "24h" });
      return res.json({ status: "success", token, role: admin.role });
    }

    // ─── ALL ROUTES BELOW REQUIRE AUTH ───────────────────
    const tokenData = verifyToken(req);
    if (!tokenData) {
      return res.status(401).json({ status: "error", message: "No autorizado. Token inválido o expirado." });
    }

    const isOwner = tokenData.role === "owner";

    // ─── STATS ───────────────────────────────────────────
    if (action === "stats") {
      const [clients] = await sql`SELECT COUNT(*) as count FROM users WHERE role = 'client'`;
      const [admins] = await sql`SELECT COUNT(*) as count FROM users WHERE role = 'admin'`;
      const [licenses] = await sql`SELECT COUNT(*) as count FROM licenses`;
      const [banned] = await sql`SELECT COUNT(*) as count FROM users WHERE is_banned = TRUE`;

      return res.json({
        status: "success",
        data: {
          clients: parseInt(clients.count),
          admins: parseInt(admins.count),
          licenses: parseInt(licenses.count),
          banned: parseInt(banned.count),
        },
      });
    }

    // ─── LIST USERS ──────────────────────────────────────
    if (action === "list_users") {
      const users = await sql`SELECT id, username, role, hwid, license_key, is_banned, expiry_date, created_at FROM users ORDER BY id DESC LIMIT 100`;
      return res.json({ status: "success", data: users });
    }

    // ─── CREATE USER ─────────────────────────────────────
    if (action === "create_user") {
      const { username, password, duration, role } = req.body || {};

      if (!username || !password) {
        return res.status(400).json({ status: "error", message: "Faltan datos." });
      }

      const userRole = role || "client";

      // Only owner can create admins
      if (!isOwner && userRole === "admin") {
        return res.status(403).json({ status: "error", message: "Solo el Owner puede crear Admins." });
      }

      const hashedPass = await bcrypt.hash(password, 10);
      let expiryDate = null;
      const dur = parseInt(duration) || 0;
      if (dur > 0) {
        const exp = new Date();
        exp.setDate(exp.getDate() + dur);
        expiryDate = exp.toISOString();
      }

      try {
        await sql`INSERT INTO users (username, password, role, expiry_date) VALUES (${username}, ${hashedPass}, ${userRole}, ${expiryDate})`;
        return res.json({ status: "success", message: "Usuario creado." });
      } catch (e) {
        return res.json({ status: "error", message: "El usuario ya existe." });
      }
    }

    // ─── CREATE LICENSES ─────────────────────────────────
    if (action === "create_license") {
      const { amount, duration } = req.body || {};
      const count = Math.min(parseInt(amount) || 1, 50);
      const dur = parseInt(duration) || 0;
      const created = [];

      for (let i = 0; i < count; i++) {
        const key = "ZENIHT-" + uuidv4().replace(/-/g, "").substring(0, 16).toUpperCase();
        await sql`INSERT INTO licenses (license_key, duration_days, created_by) VALUES (${key}, ${dur}, ${tokenData.username})`;
        created.push(key);
      }

      return res.json({ status: "success", message: `${count} licencia(s) creada(s).`, keys: created });
    }

    // ─── LIST LICENSES ───────────────────────────────────
    if (action === "list_licenses") {
      const licenses = await sql`SELECT * FROM licenses ORDER BY id DESC LIMIT 50`;
      return res.json({ status: "success", data: licenses });
    }

    // ─── BAN USER ────────────────────────────────────────
    if (action === "ban_user") {
      const userId = parseInt(req.body?.user_id);
      if (!userId) return res.status(400).json({ status: "error", message: "user_id requerido." });

      const [target] = await sql`SELECT role FROM users WHERE id = ${userId}`;
      if (!target) return res.json({ status: "error", message: "Usuario no encontrado." });
      if (target.role === "owner") return res.json({ status: "error", message: "No puedes banear al Owner." });
      if (target.role === "admin" && !isOwner) return res.json({ status: "error", message: "Solo el Owner puede banear a un Admin." });

      await sql`UPDATE users SET is_banned = TRUE WHERE id = ${userId}`;
      return res.json({ status: "success", message: "Usuario baneado." });
    }

    // ─── UNBAN USER ──────────────────────────────────────
    if (action === "unban_user") {
      const userId = parseInt(req.body?.user_id);
      if (!userId) return res.status(400).json({ status: "error", message: "user_id requerido." });

      await sql`UPDATE users SET is_banned = FALSE WHERE id = ${userId}`;
      return res.json({ status: "success", message: "Usuario desbaneado." });
    }

    // ─── RESET HWID ──────────────────────────────────────
    if (action === "reset_hwid") {
      const userId = parseInt(req.body?.user_id);
      if (!userId) return res.status(400).json({ status: "error", message: "user_id requerido." });

      await sql`UPDATE users SET hwid = NULL WHERE id = ${userId}`;
      return res.json({ status: "success", message: "HWID reseteado." });
    }

    // ─── DELETE USER ─────────────────────────────────────
    if (action === "delete_user") {
      const userId = parseInt(req.body?.user_id);
      if (!userId) return res.status(400).json({ status: "error", message: "user_id requerido." });

      const [target] = await sql`SELECT role FROM users WHERE id = ${userId}`;
      if (!target) return res.json({ status: "error", message: "Usuario no encontrado." });
      if (target.role === "owner") return res.json({ status: "error", message: "No puedes eliminar al Owner." });
      if (target.role === "admin" && !isOwner) return res.json({ status: "error", message: "Solo el Owner puede eliminar Admins." });

      await sql`DELETE FROM users WHERE id = ${userId}`;
      return res.json({ status: "success", message: "Usuario eliminado." });
    }

    // ─── DELETE LICENSE ──────────────────────────────────
    if (action === "delete_license") {
      const licenseId = parseInt(req.body?.license_id);
      if (!licenseId) return res.status(400).json({ status: "error", message: "license_id requerido." });

      await sql`DELETE FROM licenses WHERE id = ${licenseId}`;
      return res.json({ status: "success", message: "Licencia eliminada." });
    }

    return res.status(400).json({ status: "error", message: "Acción inválida." });
  } catch (err) {
    console.error("Admin API Error:", err);
    return res.status(500).json({ status: "error", message: "Error interno del servidor." });
  }
};
