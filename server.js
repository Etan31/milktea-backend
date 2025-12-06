// server.js (Fixed: delete/edit user & admin, product endpoints, orders + notifications)
// Full file — includes a POST /api/products/update endpoint for the admin edit button
import express from "express";
import session from "express-session";
import bcrypt from "bcrypt";
import dotenv from "dotenv";
import cors from "cors";
import pool from "./db.js";
import path from "path";
import { fileURLToPath } from "url";
import fs from "fs";
import admin from "firebase-admin"; // Keep this
import { v4 as uuidv4 } from "uuid";
dotenv.config();

// Fix __dirname for ESM
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();

// Optional Firebase Admin (if you have key). If missing, server still works with Postgres notifications.
const serviceAccountPath = path.join(
  __dirname,
  "milktea-2492d-firebase-adminsdk-fbsvc-81580eb8ca.json"
);
let firebaseDB = null;
if (fs.existsSync(serviceAccountPath)) {
  try {
    const serviceAccount = JSON.parse(
      fs.readFileSync(serviceAccountPath, "utf8")
    );
    const initOpts = { credential: admin.credential.cert(serviceAccount) };
    if (process.env.FIREBASE_DATABASE_URL)
      initOpts.databaseURL = process.env.FIREBASE_DATABASE_URL;
    admin.initializeApp(initOpts);
    try {
      firebaseDB = admin.database();
      console.log("🔔 Firebase Realtime DB available (optional)");
    } catch (e) {
      firebaseDB = null;
      console.warn(
        "Firebase Admin init ok but realtime DB not available - continuing without it."
      );
    }
  } catch (e) {
    console.warn(
      "Failed to parse milktea-2492d-firebase-adminsdk-fbsvc-81580eb8ca.json - continuing without Firebase."
    );
  }
} else {
  console.warn(
    "milktea-2492d-firebase-adminsdk-fbsvc-81580eb8ca.json not found — running without Firebase Realtime DB."
  );
}

// Middleware
app.use(express.json({ limit: "50mb" }));
app.use(express.urlencoded({ extended: true, limit: "50mb" }));
app.use(cors({ origin: true, credentials: true }));

app.use(
  session({
    secret: process.env.SESSION_SECRET || "default_secret",
    resave: false,
    saveUninitialized: false,
    cookie: { secure: false, httpOnly: true, maxAge: 86400000 },
  })
);

// ------------------------------------
// FIX STATIC PUBLIC PATH
// ------------------------------------
app.use(express.static(path.join(__dirname, "../public")));

app.get("/test-firebase", async (req, res) => {
  try {
    if (!firebaseDB)
      return res.json({ ok: false, message: "Firebase not initialized" });

    await firebaseDB.ref("/test").set({
      message: "Hello, Firebase!",
      time: Date.now(),
    });

    res.json({ ok: true });
  } catch (err) {
    res.json({ ok: false, error: err.message });
  }
});

// Ensure tables (users, admin_accounts, products, orders, done_orders, notifications)
const ensureTables = async () => {
  try {
    await pool.query(`
      CREATE TABLE IF NOT EXISTS users (
        id SERIAL PRIMARY KEY,
        uid TEXT UNIQUE,
        fullname TEXT,
        username TEXT,
        email TEXT UNIQUE,
        phone TEXT,
        gender TEXT,
        password TEXT,
        role TEXT DEFAULT 'user',
        created_at TIMESTAMP DEFAULT NOW()
      );
    `);

    await pool.query(`
      CREATE TABLE IF NOT EXISTS admin_accounts (
        id SERIAL PRIMARY KEY,
        uid TEXT UNIQUE,
        fullname TEXT,
        username TEXT,
        email TEXT UNIQUE,
        phone TEXT,
        gender TEXT,
        password TEXT,
        role TEXT DEFAULT 'admin',
        created_at TIMESTAMP DEFAULT NOW()
      );
    `);

    await pool.query(`
      CREATE TABLE IF NOT EXISTS products (
        id TEXT PRIMARY KEY,
        name TEXT NOT NULL,
        price NUMERIC(10,2) NOT NULL,
        image_url TEXT,
        created_at TIMESTAMP DEFAULT NOW()
      );
    `);

    await pool.query(`
      CREATE TABLE IF NOT EXISTS orders (
        order_id SERIAL PRIMARY KEY,
        user_id INTEGER,
        firebase_uid TEXT,
        customer_email TEXT,
        items JSONB,
        delivery_info JSONB,
        total_amount NUMERIC(10,2),
        payment_method TEXT,
        status TEXT DEFAULT 'pending',
        created_at TIMESTAMP DEFAULT NOW()
      );
    `);

    await pool.query(`
      CREATE TABLE IF NOT EXISTS done_orders (
        id SERIAL PRIMARY KEY,
        original_order_id INTEGER,
        user_id INTEGER,
        firebase_uid TEXT,
        customer_email TEXT,
        items JSONB,
        delivery_info JSONB,
        total_amount NUMERIC(10,2),
        payment_method TEXT,
        status TEXT,
        created_at TIMESTAMP,
        delivered_at TIMESTAMP DEFAULT NOW()
      );
    `);

    await pool.query(`
      CREATE TABLE IF NOT EXISTS notifications (
        id SERIAL PRIMARY KEY,
        user_uid TEXT,
        order_id INTEGER,
        message TEXT,
        status TEXT,
        created_at TIMESTAMP DEFAULT NOW()
      );
    `);

    console.log(
      "✅ Database tables ready (users, admin_accounts, products, orders, done_orders, notifications)"
    );
  } catch (err) {
    console.error("❌ ensureTables error:", err);
  }
};
ensureTables();

const safeJsonError = (res, status = 500, msg = "Server error") =>
  res.status(status).json({ success: false, message: msg });

/* -----------------------
   AUTH: login/register/logout
   ----------------------- */
app.post("/api/login", async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password)
      return safeJsonError(res, 400, "Email & password required");

    const result = await pool.query(
      "SELECT * FROM users WHERE email=$1 LIMIT 1",
      [email]
    );
    if (result.rows.length === 0)
      return safeJsonError(res, 404, "User not found");

    const user = result.rows[0];
    const match = await bcrypt.compare(password, user.password || "");
    if (!match) return safeJsonError(res, 401, "Wrong password");

    req.session.user = {
      id: user.id,
      uid: user.uid,
      fullname: user.fullname,
      email: user.email,
      role: user.role,
    };
    res.json({ success: true, user: req.session.user });
  } catch (err) {
    console.error("Login error:", err);
    safeJsonError(res);
  }
});

app.post("/api/register", async (req, res) => {
  try {
    const { fullname, username, email, phone, gender, password } = req.body;
    if (!fullname || !email || !password)
      return safeJsonError(res, 400, "fullname, email, password required");

    const uid = uuidv4();
    const hashed = await bcrypt.hash(password, 12);

    const r = await pool.query(
      `INSERT INTO users (uid, fullname, username, email, phone, gender, password)
       VALUES ($1,$2,$3,$4,$5,$6,$7) RETURNING *`,
      [
        uid,
        fullname,
        username || null,
        email,
        phone || null,
        gender || null,
        hashed,
      ]
    );

    res.json({ success: true, user: r.rows[0] });
  } catch (err) {
    console.error("Register error:", err);
    safeJsonError(res);
  }
});

app.post("/api/logout", (req, res) => {
  req.session.destroy(() => res.json({ success: true }));
});

/* -----------------------
   Admin login by Firebase UID (optional)
   ----------------------- */
app.post("/api/admin-uid-login", async (req, res) => {
  try {
    const { uid } = req.body;
    if (!uid) return safeJsonError(res, 400, "Missing uid");
    const r = await pool.query(
      "SELECT * FROM admin_accounts WHERE uid=$1 LIMIT 1",
      [uid]
    );
    if (r.rows.length === 0) return safeJsonError(res, 404, "Admin not found");
    req.session.admin = r.rows[0];
    res.json({ success: true, admin: r.rows[0] });
  } catch (err) {
    console.error("Admin login error:", err);
    safeJsonError(res);
  }
});

/* -----------------------
   FETCH endpoints
   ----------------------- */
app.get("/api/users", async (req, res) => {
  try {
    const r = await pool.query(
      "SELECT id, uid, fullname, username, email, phone, gender, role, created_at FROM users ORDER BY id ASC"
    );
    res.json({ success: true, users: r.rows });
  } catch (err) {
    console.error("Fetch users error:", err);
    safeJsonError(res);
  }
});

app.get("/api/admins", async (req, res) => {
  try {
    const r = await pool.query(
      "SELECT id, uid, fullname, username, email, phone, gender, role, created_at FROM admin_accounts ORDER BY id ASC"
    );
    res.json({ success: true, admins: r.rows });
  } catch (err) {
    console.error("Fetch admins error:", err);
    safeJsonError(res);
  }
});

app.get("/api/products", async (req, res) => {
  try {
    const r = await pool.query(
      "SELECT * FROM products ORDER BY created_at DESC"
    );
    res.json({ success: true, products: r.rows });
  } catch (err) {
    console.error("Fetch products error:", err);
    safeJsonError(res);
  }
});

/* -----------------------
   Products: create / update / delete
   - frontend calls POST /api/products (body { name, price, image_url })
   - frontend edit will call POST /api/products/update (body { product_id, name, price, image_url })
   - for delete, frontend calls POST /api/delete-product with { product_id }
   ----------------------- */
app.post("/api/products", async (req, res) => {
  try {
    const { name, price, image_url } = req.body;
    if (!name || price == null)
      return safeJsonError(res, 400, "name & price required");

    const id = Date.now().toString(); // simple id to match your Firebase keys
    const r = await pool.query(
      `INSERT INTO products (id, name, price, image_url) VALUES ($1,$2,$3,$4) RETURNING *`,
      [id, name, Number(price), image_url || null]
    );
    res.json({ success: true, product: r.rows[0] });
  } catch (err) {
    console.error("Create product error:", err);
    safeJsonError(res);
  }
});

// keep PUT /api/products/:id for API compatibility
app.put("/api/products/:id", async (req, res) => {
  try {
    const { id } = req.params;
    const { name, price, image_url } = req.body;
    const r = await pool.query(
      `UPDATE products SET name=$1, price=$2, image_url=$3 WHERE id=$4 RETURNING *`,
      [name, price, image_url, id]
    );
    res.json({ success: true, product: r.rows[0] });
  } catch (err) {
    console.error("Update product error:", err);
    safeJsonError(res);
  }
});

// NEW: endpoint used by admin.html edit button (POST)
app.post("/api/products/update", async (req, res) => {
  try {
    const { product_id, name, price, image_url } = req.body;
    if (!product_id || !name || price == null)
      return safeJsonError(res, 400, "product_id, name & price required");

    const r = await pool.query(
      `UPDATE products SET name=$1, price=$2, image_url=$3 WHERE id=$4 RETURNING *`,
      [name, Number(price), image_url || null, product_id]
    );

    res.json({ success: true, product: r.rows[0] });
  } catch (err) {
    console.error("Update product (POST) error:", err);
    safeJsonError(res);
  }
});

app.post("/api/delete-product", async (req, res) => {
  try {
    const { product_id } = req.body;
    if (!product_id) return safeJsonError(res, 400, "Missing product_id");
    await pool.query("DELETE FROM products WHERE id=$1", [product_id]);
    res.json({ success: true });
  } catch (err) {
    console.error("Delete product error:", err);
    safeJsonError(res);
  }
});

/* -----------------------
   Delete / Update User & Admin endpoints
   Front-end sends uid (Firebase uid stored in uid column)
   ----------------------- */

app.post("/api/admin/register", async (req, res) => {
  try {
    const { fullname, username, email, phone, gender, password } = req.body;
    if (!fullname || !email || !password)
      return safeJsonError(res, 400, "fullname, email, password required");

    const uid = uuidv4();
    const hashed = await bcrypt.hash(password, 12);

    const r = await pool.query(
      `INSERT INTO admin_accounts (uid, fullname, username, email, phone, gender, password)
       VALUES ($1,$2,$3,$4,$5,$6,$7) RETURNING *`,
      [
        uid,
        fullname,
        username || null,
        email,
        phone || null,
        gender || null,
        hashed,
      ]
    );

    res.json({ success: true, admin: r.rows[0] });
  } catch (err) {
    console.error("Admin register error:", err);
    safeJsonError(res);
  }
});

// Delete a user by uid
app.post("/api/delete-user", async (req, res) => {
  try {
    const { uid } = req.body;
    if (!uid) return safeJsonError(res, 400, "Missing uid");
    // Optionally: cascade delete their orders, notifications, etc. — current behaviour: delete user row only
    await pool.query("DELETE FROM users WHERE uid=$1", [uid]);
    // Also remove any notifications records for that uid
    await pool.query("DELETE FROM notifications WHERE user_uid=$1", [uid]);
    res.json({ success: true });
  } catch (err) {
    console.error("Delete user error:", err);
    safeJsonError(res);
  }
});

// Delete an admin by uid
app.post("/api/delete-admin", async (req, res) => {
  try {
    const { uid } = req.body;
    if (!uid) return safeJsonError(res, 400, "Missing uid");
    await pool.query("DELETE FROM admin_accounts WHERE uid=$1", [uid]);
    res.json({ success: true });
  } catch (err) {
    console.error("Delete admin error:", err);
    safeJsonError(res);
  }
});

// Update user fields by uid (e.g., fullname, email, phone, role)
app.post("/api/users/update", async (req, res) => {
  try {
    const { uid, fullname, username, email, phone, gender, role } = req.body;
    if (!uid) return safeJsonError(res, 400, "Missing uid");
    // Build dynamic update
    const fields = [];
    const values = [];
    let idx = 1;
    if (fullname !== undefined) {
      fields.push(`fullname=$${idx++}`);
      values.push(fullname);
    }
    if (username !== undefined) {
      fields.push(`username=$${idx++}`);
      values.push(username);
    }
    if (email !== undefined) {
      fields.push(`email=$${idx++}`);
      values.push(email);
    }
    if (phone !== undefined) {
      fields.push(`phone=$${idx++}`);
      values.push(phone);
    }
    if (gender !== undefined) {
      fields.push(`gender=$${idx++}`);
      values.push(gender);
    }
    if (role !== undefined) {
      fields.push(`role=$${idx++}`);
      values.push(role);
    }
    if (fields.length === 0)
      return safeJsonError(res, 400, "No fields to update");
    values.push(uid);
    const q = `UPDATE users SET ${fields.join(", ")} WHERE uid=$${
      values.length
    } RETURNING *`;
    const r = await pool.query(q, values);
    res.json({ success: true, user: r.rows[0] });
  } catch (err) {
    console.error("Update user error:", err);
    safeJsonError(res);
  }
});

// Update admin fields by uid
app.post("/api/admins/update", async (req, res) => {
  try {
    const { uid, fullname, username, email, phone, gender, role } = req.body;
    if (!uid) return safeJsonError(res, 400, "Missing uid");
    const fields = [];
    const values = [];
    let idx = 1;
    if (fullname !== undefined) {
      fields.push(`fullname=$${idx++}`);
      values.push(fullname);
    }
    if (username !== undefined) {
      fields.push(`username=$${idx++}`);
      values.push(username);
    }
    if (email !== undefined) {
      fields.push(`email=$${idx++}`);
      values.push(email);
    }
    if (phone !== undefined) {
      fields.push(`phone=$${idx++}`);
      values.push(phone);
    }
    if (gender !== undefined) {
      fields.push(`gender=$${idx++}`);
      values.push(gender);
    }
    if (role !== undefined) {
      fields.push(`role=$${idx++}`);
      values.push(role);
    }
    if (fields.length === 0)
      return safeJsonError(res, 400, "No fields to update");
    values.push(uid);
    const q = `UPDATE admin_accounts SET ${fields.join(", ")} WHERE uid=$${
      values.length
    } RETURNING *`;
    const r = await pool.query(q, values);
    res.json({ success: true, admin: r.rows[0] });
  } catch (err) {
    console.error("Update admin error:", err);
    safeJsonError(res);
  }
});

/* -----------------------
   ORDERS endpoints (create, list, ongoing, update-status -> move delivered -> notifications)
   ----------------------- */

app.post("/api/orders/create", async (req, res) => {
  try {
    const {
      user_id,
      email,
      items,
      total_amount,
      payment_method,
      delivery_info,
    } = req.body;
    const firebaseUidFromClient = user_id || null;
    let pgUserId = null;
    if (firebaseUidFromClient) {
      const u = await pool.query("SELECT id FROM users WHERE uid=$1 LIMIT 1", [
        firebaseUidFromClient,
      ]);
      if (u.rows.length > 0) pgUserId = u.rows[0].id;
    }
    const r = await pool.query(
      `INSERT INTO orders (user_id, firebase_uid, customer_email, items, delivery_info, total_amount, payment_method, status)
       VALUES ($1,$2,$3,$4,$5,$6,$7,'pending')
       RETURNING *`,
      [
        pgUserId,
        firebaseUidFromClient,
        email,
        JSON.stringify(items || []),
        JSON.stringify(delivery_info || {}),
        total_amount || 0,
        payment_method || null,
      ]
    );
    res.json({ success: true, order: r.rows[0] });
  } catch (err) {
    console.error("Create order error:", err);
    safeJsonError(res);
  }
});

app.get("/api/orders", async (req, res) => {
  try {
    const r = await pool.query(`
      SELECT o.*, u.fullname AS customer_name, u.uid AS user_uid
      FROM orders o
      LEFT JOIN users u ON u.id = o.user_id
      ORDER BY o.created_at DESC
    `);
    res.json({ success: true, orders: r.rows });
  } catch (err) {
    console.error("Fetch orders error:", err);
    safeJsonError(res);
  }
});

app.get("/api/orders/ongoing", async (req, res) => {
  try {
    const r = await pool.query(`
      SELECT o.*, u.fullname AS customer_name, u.uid AS user_uid
      FROM orders o
      LEFT JOIN users u ON u.id = o.user_id
      WHERE COALESCE(o.status,'pending') NOT IN ('delivered','completed')
      ORDER BY o.created_at DESC
    `);
    res.json({ success: true, orders: r.rows });
  } catch (err) {
    console.error("Fetch ongoing orders error:", err);
    safeJsonError(res);
  }
});

// Update status: update, create notification, and move delivered -> done_orders safely
app.post("/api/orders/update-status", async (req, res) => {
  const { order_id, status } = req.body;
  if (!order_id || !status)
    return safeJsonError(res, 400, "Missing order_id or status");

  const client = await pool.connect();
  try {
    await client.query("BEGIN");

    // fetch the order
    const ordRes = await client.query(
      "SELECT * FROM orders WHERE order_id=$1 LIMIT 1",
      [order_id]
    );
    if (ordRes.rows.length === 0) {
      await client.query("ROLLBACK");
      return safeJsonError(res, 404, "Order not found");
    }
    const order = ordRes.rows[0];

    // update status
    await client.query("UPDATE orders SET status=$1 WHERE order_id=$2", [
      status,
      order_id,
    ]);

    // notifications message
    const notifMsg = `Order #${order_id} status updated to ${status}`;

    // attempt to figure user UID
    let userUid = order.firebase_uid || null;
    if (!userUid && order.user_id) {
      const u = await client.query(
        "SELECT uid FROM users WHERE id=$1 LIMIT 1",
        [order.user_id]
      );
      if (u.rows.length > 0) userUid = u.rows[0].uid;
    }

    // insert server-side notifications record (always)
    await client.query(
      `INSERT INTO notifications (user_uid, order_id, message, status) VALUES ($1,$2,$3,$4)`,
      [userUid, order_id, notifMsg, status]
    );

    // push to Firebase realtime DB if available
    if (firebaseDB && userUid) {
      try {
        const notifRef = firebaseDB.ref(`notifications/${userUid}`);
        await notifRef.push({
          order_id,
          status,
          message: notifMsg,
          created_at: new Date().toISOString(),
        });
      } catch (e) {
        console.warn("Failed to push to Firebase realtime DB:", e.message || e);
      }
    }

    // if delivered -> move to done_orders then delete original
    if ((status || "").toLowerCase() === "delivered") {
      // parse JSON fields safely
      let safeItems = order.items;
      let safeDelivery = order.delivery_info;
      try {
        if (typeof safeItems === "string") safeItems = JSON.parse(safeItems);
      } catch (e) {
        safeItems = [];
      }
      try {
        if (typeof safeDelivery === "string")
          safeDelivery = JSON.parse(safeDelivery);
      } catch (e) {
        safeDelivery = {};
      }

      await client.query(
        `INSERT INTO done_orders (original_order_id, user_id, firebase_uid, customer_email, items, delivery_info, total_amount, payment_method, status, created_at)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`,
        [
          order.order_id,
          order.user_id,
          order.firebase_uid || null,
          order.customer_email || null,
          JSON.stringify(safeItems),
          JSON.stringify(safeDelivery),
          order.total_amount || 0,
          order.payment_method || null,
          "completed",
          order.created_at || new Date(),
        ]
      );

      await client.query("DELETE FROM orders WHERE order_id=$1", [order_id]);
    }

    await client.query("COMMIT");
    res.json({ success: true });
  } catch (err) {
    await client.query("ROLLBACK");
    console.error("Update status error:", err);
    safeJsonError(res);
  } finally {
    client.release();
  }
});

/* -----------------------
   Done orders list
   ----------------------- */
app.get("/api/orders/done", async (req, res) => {
  try {
    const r = await pool.query(`
      SELECT d.*, u.fullname AS customer_name, u.email AS customer_email
      FROM done_orders d
      LEFT JOIN users u ON u.id = d.user_id
      ORDER BY d.delivered_at DESC
    `);
    res.json({ success: true, done_orders: r.rows });
  } catch (err) {
    console.error("Fetch done orders error:", err);
    safeJsonError(res);
  }
});

// Static & fallback
app.use(express.static(path.join(__dirname, "public")));
app.use((req, res) =>
  res.sendFile(path.join(__dirname, "public", "index.html"))
);

// Start
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`🚀 Server running on port ${PORT}`));
