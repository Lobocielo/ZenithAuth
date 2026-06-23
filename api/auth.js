// Auth API — handles login, register, and verify for C++ client
const bcrypt = require("bcryptjs");
const { getDb, initDb } = require("./_db");

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

    // ─── LOGIN ───────────────────────────────────────────
    if (action === "login") {
      const { username, password, hwid } = req.method === "POST" ? req.body : req.query;

      if (!username || !password) {
        return res.status(400).json({ status: "error", message: "Faltan credenciales." });
      }

      const users = await sql`SELECT * FROM users WHERE username = ${username}`;
      const user = users[0];

      if (!user || !(await bcrypt.compare(password, user.password))) {
        return res.json({ status: "error", message: "Usuario o contraseña incorrectos." });
      }

      if (user.is_banned) {
        return res.json({ status: "error", message: "Cuenta baneada." });
      }

      // Check subscription expiry
      if (user.expiry_date !== null) {
        const expiry = new Date(user.expiry_date);
        if (Date.now() > expiry.getTime()) {
          return res.json({ status: "error", message: "La suscripción ha expirado." });
        }
      }

      // HWID check
      if (hwid) {
        if (!user.hwid) {
          // First login — bind HWID
          await sql`UPDATE users SET hwid = ${hwid} WHERE id = ${user.id}`;
        } else if (user.hwid !== hwid) {
          return res.json({ status: "error", message: "HWID Invalido." });
        }
      }

      // Calculate days left
      let daysLeft = "Permanente";
      if (user.expiry_date !== null) {
        const diff = new Date(user.expiry_date).getTime() - Date.now();
        daysLeft = Math.round(diff / 86400000) + " días";
      }

      return res.json({
        status: "success",
        message: "Login correcto.",
        subscription: daysLeft,
        role: user.role,
      });
    }

    // ─── REGISTER ────────────────────────────────────────
    if (action === "register") {
      const { username, password, license } = req.body || {};

      if (!username || !password || !license) {
        return res.status(400).json({ status: "error", message: "Faltan datos." });
      }

      // Validate license
      const licenses = await sql`SELECT * FROM licenses WHERE license_key = ${license} AND is_used = FALSE`;
      const validLicense = licenses[0];

      if (!validLicense) {
        return res.json({ status: "error", message: "Licencia inválida o ya en uso." });
      }

      // Check if user exists
      const existing = await sql`SELECT id FROM users WHERE username = ${username}`;
      if (existing.length > 0) {
        return res.json({ status: "error", message: "El usuario ya existe." });
      }

      const hashedPass = await bcrypt.hash(password, 10);

      // Calculate expiry
      let expiryDate = null;
      if (validLicense.duration_days > 0) {
        const exp = new Date();
        exp.setDate(exp.getDate() + validLicense.duration_days);
        expiryDate = exp.toISOString();
      }

      await sql`
        INSERT INTO users (username, password, license_key, expiry_date)
        VALUES (${username}, ${hashedPass}, ${license}, ${expiryDate})
      `;

      // Mark license as used
      await sql`UPDATE licenses SET is_used = TRUE WHERE license_key = ${license}`;

      return res.json({ status: "success", message: "Registro exitoso." });
    }

    // ─── VERIFY (for C++ client to check if session is still valid) ──
    if (action === "verify") {
      const { username, hwid } = req.method === "POST" ? req.body : req.query;

      if (!username || !hwid) {
        return res.status(400).json({ status: "error", message: "Faltan datos." });
      }

      const users = await sql`SELECT * FROM users WHERE username = ${username} AND hwid = ${hwid}`;
      const user = users[0];

      if (!user) {
        return res.json({ status: "error", message: "Sesión inválida." });
      }

      if (user.is_banned) {
        return res.json({ status: "error", message: "Cuenta baneada." });
      }

      if (user.expiry_date !== null && Date.now() > new Date(user.expiry_date).getTime()) {
        return res.json({ status: "error", message: "Suscripción expirada." });
      }

      return res.json({ status: "success", message: "Sesión válida." });
    }

    return res.status(400).json({ status: "error", message: "Acción inválida." });
  } catch (err) {
    console.error("Auth API Error:", err);
    return res.status(500).json({ status: "error", message: "Error interno del servidor." });
  }
};
