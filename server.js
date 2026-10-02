const express = require("express");
const path = require("path");
const fs = require("fs");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const cookieParser = require("cookie-parser");
const Database = require("better-sqlite3");

const app = express();

const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || "hmp-dev-secret";
const ADMIN_USER = process.env.ADMIN_USER || "admin";
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || "123456";
const DB_PATH = process.env.DB_PATH || path.join(__dirname, "hmp.sqlite");

const dbDir = path.dirname(DB_PATH);
if (!fs.existsSync(dbDir)) fs.mkdirSync(dbDir, { recursive: true });

const db = new Database(DB_PATH);
db.pragma("journal_mode = WAL");

app.use(express.json({ limit: "10mb" }));
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());

db.exec(`
CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  username TEXT UNIQUE NOT NULL,
  password_hash TEXT NOT NULL,
  created_at TEXT DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS products (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL,
  code TEXT DEFAULT '',
  unit TEXT DEFAULT '',
  cost REAL DEFAULT 0,
  price REAL DEFAULT 0,
  stock REAL DEFAULT 0,
  image TEXT DEFAULT '',
  description TEXT DEFAULT '',
  created_at TEXT DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS customers (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL,
  phone TEXT DEFAULT '',
  address TEXT DEFAULT '',
  due REAL DEFAULT 0,
  created_at TEXT DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS invoices (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  no TEXT,
  date TEXT,
  customer TEXT,
  address TEXT DEFAULT '',
  pay TEXT DEFAULT '',
  total REAL DEFAULT 0,
  items_json TEXT DEFAULT '[]',
  created_at TEXT DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS challans (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  no TEXT,
  date TEXT,
  customer TEXT,
  address TEXT DEFAULT '',
  items_json TEXT DEFAULT '[]',
  created_at TEXT DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS purchases (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  date TEXT,
  supplier TEXT DEFAULT '',
  product TEXT DEFAULT '',
  qty REAL DEFAULT 0,
  price REAL DEFAULT 0,
  total REAL DEFAULT 0,
  created_at TEXT DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS expenses (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  date TEXT,
  type TEXT DEFAULT '',
  amount REAL DEFAULT 0,
  note TEXT DEFAULT '',
  created_at TEXT DEFAULT CURRENT_TIMESTAMP
);
`);

const oldAdmin = db.prepare("SELECT id FROM users WHERE username = ?").get(ADMIN_USER);

if (!oldAdmin) {
  const hash = bcrypt.hashSync(ADMIN_PASSWORD, 10);
  db.prepare(
    "INSERT INTO users (username, password_hash) VALUES (?, ?)"
  ).run(ADMIN_USER, hash);
}

function makeToken(user) {
  return jwt.sign(
    { id: user.id, username: user.username },
    JWT_SECRET,
    { expiresIn: "7d" }
  );
}

function auth(req, res, next) {
  try {
    const token = req.cookies.hmp_token;

    if (!token) {
      return res.status(401).json({ error: "অনুগ্রহ করে লগইন করুন" });
    }

    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch (e) {
    return res.status(401).json({ error: "সেশন শেষ হয়েছে। আবার লগইন করুন।" });
  }
}

app.get("/health", (req, res) => {
  res.json({ ok: true, service: "HMP Printing" });
});

app.post("/api/login", (req, res) => {
  const username = String(req.body.username || "").trim();
  const password = String(req.body.password || "");

  const user = db
    .prepare("SELECT * FROM users WHERE username = ?")
    .get(username);

  if (!user || !bcrypt.compareSync(password, user.password_hash)) {
    return res.status(401).json({
      error: "ভুল Username অথবা Password"
    });
  }

  const token = makeToken(user);

  res.cookie("hmp_token", token, {
    httpOnly: true,
    sameSite: "lax",
    secure: process.env.NODE_ENV === "production",
    maxAge: 7 * 24 * 60 * 60 * 1000
  });

  res.json({
    ok: true,
    user: { id: user.id, username: user.username }
  });
});

app.post("/api/logout", (req, res) => {
  res.clearCookie("hmp_token");
  res.json({ ok: true });
});

app.get("/api/me", auth, (req, res) => {
  res.json({
    ok: true,
    user: req.user
  });
});

/* PRODUCTS */

app.get("/api/products", auth, (req, res) => {
  const rows = db
    .prepare("SELECT * FROM products ORDER BY id DESC")
    .all();

  res.json(rows);
});

app.post("/api/products", auth, (req, res) => {
  const b = req.body;

  const result = db.prepare(`
    INSERT INTO products
    (name, code, unit, cost, price, stock, image, description)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
  `).run(
    b.name || "",
    b.code || "",
    b.unit || "",
    Number(b.cost || 0),
    Number(b.price || 0),
    Number(b.stock || 0),
    b.image || "",
    b.description || ""
  );

  res.json({ ok: true, id: result.lastInsertRowid });
});

app.delete("/api/products/:id", auth, (req, res) => {
  db.prepare("DELETE FROM products WHERE id = ?")
    .run(Number(req.params.id));

  res.json({ ok: true });
});

/* CUSTOMERS */

app.get("/api/customers", auth, (req, res) => {
  res.json(
    db.prepare("SELECT * FROM customers ORDER BY id DESC").all()
  );
});

app.post("/api/customers", auth, (req, res) => {
  const b = req.body;

  const result = db.prepare(`
    INSERT INTO customers (name, phone, address, due)
    VALUES (?, ?, ?, ?)
  `).run(
    b.name || "",
    b.phone || "",
    b.address || "",
    Number(b.due || 0)
  );

  res.json({ ok: true, id: result.lastInsertRowid });
});

/* DASHBOARD */

app.get("/api/dashboard", auth, (req, res) => {
  const sales =
    db.prepare("SELECT COALESCE(SUM(total),0) AS n FROM invoices").get().n;

  const buy =
    db.prepare("SELECT COALESCE(SUM(total),0) AS n FROM purchases").get().n;

  const exp =
    db.prepare("SELECT COALESCE(SUM(amount),0) AS n FROM expenses").get().n;

  const due =
    db.prepare("SELECT COALESCE(SUM(due),0) AS n FROM customers").get().n;

  const products =
    db.prepare("SELECT COUNT(*) AS n FROM products").get().n;

  res.json({
    sales: Number(sales),
    purchase: Number(buy),
    expenses: Number(exp),
    due: Number(due),
    products: Number(products),
    profit: Number(sales) - Number(buy) - Number(exp)
  });
});

/* INVOICES */

app.get("/api/invoices", auth, (req, res) => {
  const rows = db
    .prepare("SELECT * FROM invoices ORDER BY id DESC")
    .all();

  res.json(
    rows.map(r => ({
      ...r,
      items: JSON.parse(r.items_json || "[]")
    }))
  );
});

app.post("/api/invoices", auth, (req, res) => {
  const b = req.body;
  const items = Array.isArray(b.items) ? b.items : [];

  let total = Number(b.total || 0);

  if (!total) {
    total = items.reduce((sum, item) => {
      return sum +
        Number(item.qty || 0) *
        Number(item.rate || item.price || 0);
    }, 0);
  }

  const insert = db.prepare(`
    INSERT INTO invoices
    (no, date, customer, address, pay, total, items_json)
    VALUES (?, ?, ?, ?, ?, ?, ?)
  `);

  const updateStock = db.prepare(`
    UPDATE products
    SET stock = stock - ?
    WHERE name = ?
  `);

  const updateDue = db.prepare(`
    UPDATE customers
    SET due = due + ?
    WHERE name = ?
  `);

  const transaction = db.transaction(() => {
    const result = insert.run(
      b.no || "",
      b.date || new Date().toISOString().slice(0, 10),
      b.customer || "",
      b.address || "",
      b.pay || "",
      total,
      JSON.stringify(items)
    );

    for (const item of items) {
      const qty = Number(item.qty || 0);
      const name = item.product || item.name || "";

      if (qty && name) {
        updateStock.run(qty, name);
      }
    }

    const payText = String(b.pay || "").toLowerCase();

    if (
      b.customer &&
      (payText.includes("বাকি") ||
       payText.includes("due") ||
       payText.includes("credit"))
    ) {
      updateDue.run(total, b.customer);
    }

    return result.lastInsertRowid;
  });

  const id = transaction();

  res.json({ ok: true, id });
});

/* CHALLANS */

app.get("/api/challans", auth, (req, res) => {
  const rows = db
    .prepare("SELECT * FROM challans ORDER BY id DESC")
    .all();

  res.json(
    rows.map(r => ({
      ...r,
      items: JSON.parse(r.items_json || "[]")
    }))
  );
});

app.post("/api/challans", auth, (req, res) => {
  const b = req.body;
  const items = Array.isArray(b.items) ? b.items : [];

  const result = db.prepare(`
    INSERT INTO challans
    (no, date, customer, address, items_json)
    VALUES (?, ?, ?, ?, ?)
  `).run(
    b.no || "",
    b.date || new Date().toISOString().slice(0, 10),
    b.customer || "",
    b.address || "",
    JSON.stringify(items)
  );

  res.json({ ok: true, id: result.lastInsertRowid });
});

/* PURCHASES */

app.get("/api/purchases", auth, (req, res) => {
  res.json(
    db.prepare("SELECT * FROM purchases ORDER BY id DESC").all()
  );
});

app.post("/api/purchases", auth, (req, res) => {
  const b = req.body;

  const qty = Number(b.qty || 0);
  const price = Number(b.price || 0);
  const total = Number(b.total || qty * price);

  const transaction = db.transaction(() => {
    const result = db.prepare(`
      INSERT INTO purchases
      (date, supplier, product, qty, price, total)
      VALUES (?, ?, ?, ?, ?, ?)
    `).run(
      b.date || new Date().toISOString().slice(0, 10),
      b.supplier || "",
      b.product || "",
      qty,
      price,
      total
    );

    if (b.product) {
      db.prepare(`
        UPDATE products
        SET stock = stock + ?
        WHERE name = ?
      `).run(qty, b.product);
    }

    return result.lastInsertRowid;
  });

  res.json({
    ok: true,
    id: transaction()
  });
});

/* EXPENSES */

app.get("/api/expenses", auth, (req, res) => {
  res.json(
    db.prepare("SELECT * FROM expenses ORDER BY id DESC").all()
  );
});

app.post("/api/expenses
