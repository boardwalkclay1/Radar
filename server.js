// server.js
// Blip Radar backend – single-file, real flows, SQLite + ws

const path = require("path");
const fs = require("fs");
const http = require("http");
const express = require("express");
const sqlite3 = require("sqlite3").verbose();
const bcrypt = require("bcrypt");
const crypto = require("crypto");
const WebSocket = require("ws");
const cors = require("cors");

// --- CONFIG ---
const PORT = 3000;
const DB_FILE = path.join(__dirname, "radar.db");

// --- EXPRESS APP + HTTP SERVER ---
const app = express();
const server = http.createServer(app);

// --- MIDDLEWARE ---
app.use(express.json({ limit: "2mb" })); // allow base64 avatars
app.use(express.urlencoded({ extended: true }));
app.use(cors());
app.use(express.static(path.join(__dirname, "public"))); // serves index.html, radar.html, etc.

// --- SQLITE SETUP ---
const db = new sqlite3.Database(DB_FILE);

db.serialize(() => {
  // Users: core identity
  db.run(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      bio TEXT,
      avatar_base64 TEXT,
      blip_color TEXT DEFAULT '#6cf0ff',
      visible INTEGER DEFAULT 1,
      created_at TEXT DEFAULT (datetime('now'))
    )
  `);

  // Sessions: simple token auth
  db.run(`
    CREATE TABLE IF NOT EXISTS sessions (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER NOT NULL,
      token TEXT NOT NULL,
      created_at TEXT DEFAULT (datetime('now')),
      expires_at TEXT,
      FOREIGN KEY(user_id) REFERENCES users(id)
    )
  `);

  // Blips: location + status on the radar
  db.run(`
    CREATE TABLE IF NOT EXISTS blips (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER NOT NULL,
      lat REAL,
      lon REAL,
      status_message TEXT,
      updated_at TEXT DEFAULT (datetime('now')),
      FOREIGN KEY(user_id) REFERENCES users(id)
    )
  `);

  // Messages: public + private chat
  db.run(`
    CREATE TABLE IF NOT EXISTS messages (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      room_id TEXT,
      from_user_id INTEGER NOT NULL,
      to_user_id INTEGER,
      text TEXT,
      emoji_type TEXT,
      created_at TEXT DEFAULT (datetime('now')),
      FOREIGN KEY(from_user_id) REFERENCES users(id),
      FOREIGN KEY(to_user_id) REFERENCES users(id)
    )
  `);

  // Emoji events: explicit hug/kiss/hi/bye/flirt actions
  db.run(`
    CREATE TABLE IF NOT EXISTS emoji_events (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      from_user_id INTEGER NOT NULL,
      to_user_id INTEGER NOT NULL,
      type TEXT NOT NULL,
      created_at TEXT DEFAULT (datetime('now')),
      FOREIGN KEY(from_user_id) REFERENCES users(id),
      FOREIGN KEY(to_user_id) REFERENCES users(id)
    )
  `);
});

// --- HELPER FUNCTIONS ---

function generateToken() {
  return crypto.randomBytes(32).toString("hex");
}

function hashPassword(password) {
  return bcrypt.hash(password, 10);
}

function verifyPassword(password, hash) {
  return bcrypt.compare(password, hash);
}

function getUserByToken(token) {
  return new Promise((resolve, reject) => {
    if (!token) return resolve(null);
    db.get(
      `
      SELECT u.*
      FROM sessions s
      JOIN users u ON u.id = s.user_id
      WHERE s.token = ?
    `,
      [token],
      (err, row) => {
        if (err) return reject(err);
        resolve(row || null);
      }
    );
  });
}

// Auth middleware for REST routes
async function authMiddleware(req, res, next) {
  try {
    const token =
      req.headers["x-session-token"] ||
      req.headers["authorization"]?.replace("Bearer ", "");
    const user = await getUserByToken(token);
    if (!user) {
      return res.status(401).json({ error: "Unauthorized" });
    }
    req.user = user;
    next();
  } catch (e) {
    console.error("Auth error:", e);
    res.status(500).json({ error: "Internal auth error" });
  }
}

// --- AUTH ROUTES ---

// Signup
app.post("/api/signup", async (req, res) => {
  try {
    const { username, password } = req.body || {};
    if (!username || !password) {
      return res.status(400).json({ error: "username and password required" });
    }

    const passwordHash = await hashPassword(password);

    db.run(
      `
      INSERT INTO users (username, password_hash)
      VALUES (?, ?)
    `,
      [username, passwordHash],
      function (err) {
        if (err) {
          if (err.message.includes("UNIQUE")) {
            return res.status(409).json({ error: "username already taken" });
          }
          console.error("Signup error:", err);
          return res.status(500).json({ error: "failed to create user" });
        }

        const userId = this.lastID;
        const token = generateToken();

        db.run(
          `
          INSERT INTO sessions (user_id, token)
          VALUES (?, ?)
        `,
          [userId, token],
          (err2) => {
            if (err2) {
              console.error("Session create error:", err2);
              return res.status(500).json({ error: "failed to create session" });
            }
            return res.json({
              token,
              user: {
                id: userId,
                username,
                bio: "",
                avatar_base64: null,
                blip_color: "#6cf0ff",
                visible: 1
              }
            });
          }
        );
      }
    );
  } catch (e) {
    console.error("Signup exception:", e);
    res.status(500).json({ error: "internal error" });
  }
});

// Login
app.post("/api/login", (req, res) => {
  const { username, password } = req.body || {};
  if (!username || !password) {
    return res.status(400).json({ error: "username and password required" });
  }

  db.get(
    `
    SELECT * FROM users WHERE username = ?
  `,
    [username],
    async (err, user) => {
      if (err) {
        console.error("Login error:", err);
        return res.status(500).json({ error: "internal error" });
      }
      if (!user) {
        return res.status(401).json({ error: "invalid credentials" });
      }

      const valid = await verifyPassword(password, user.password_hash);
      if (!valid) {
        return res.status(401).json({ error: "invalid credentials" });
      }

      const token = generateToken();
      db.run(
        `
        INSERT INTO sessions (user_id, token)
        VALUES (?, ?)
      `,
        [user.id, token],
        (err2) => {
          if (err2) {
            console.error("Session create error:", err2);
            return res.status(500).json({ error: "failed to create session" });
          }

          res.json({
            token,
            user: {
              id: user.id,
              username: user.username,
              bio: user.bio,
              avatar_base64: user.avatar_base64,
              blip_color: user.blip_color,
              visible: user.visible
            }
          });
        }
      );
    }
  );
});

// --- PROFILE ROUTES ---

// Get current user profile
app.get("/api/me", authMiddleware, (req, res) => {
  const u = req.user;
  res.json({
    id: u.id,
    username: u.username,
    bio: u.bio,
    avatar_base64: u.avatar_base64,
    blip_color: u.blip_color,
    visible: !!u.visible
  });
});

// Update profile (username, bio, avatar_base64, blip_color, visible)
app.put("/api/me", authMiddleware, (req, res) => {
  const { username, bio, avatar_base64, blip_color, visible } = req.body || {};
  const userId = req.user.id;

  db.run(
    `
    UPDATE users
    SET username = COALESCE(?, username),
        bio = COALESCE(?, bio),
        avatar_base64 = COALESCE(?, avatar_base64),
        blip_color = COALESCE(?, blip_color),
        visible = COALESCE(?, visible)
    WHERE id = ?
  `,
    [
      username || null,
      bio || null,
      avatar_base64 || null,
      blip_color || null,
      typeof visible === "boolean" ? (visible ? 1 : 0) : null,
      userId
    ],
    function (err) {
      if (err) {
        console.error("Profile update error:", err);
        return res.status(500).json({ error: "failed to update profile" });
      }
      db.get(`SELECT * FROM users WHERE id = ?`, [userId], (err2, row) => {
        if (err2) {
          console.error("Profile fetch error:", err2);
          return res.status(500).json({ error: "failed to fetch updated profile" });
        }
        res.json({
          id: row.id,
          username: row.username,
          bio: row.bio,
          avatar_base64: row.avatar_base64,
          blip_color: row.blip_color,
          visible: !!row.visible
        });
      });
    }
  );
});

// --- BLIP / RADAR ROUTES ---

// Update blip (location + status_message)
app.post("/api/blip/update", authMiddleware, (req, res) => {
  const userId = req.user.id;
  const { lat, lon, status_message } = req.body || {};

  db.get(
    `
    SELECT id FROM blips WHERE user_id = ?
  `,
    [userId],
    (err, row) => {
      if (err) {
        console.error("Blip fetch error:", err);
        return res.status(500).json({ error: "failed to fetch blip" });
      }

      const now = new Date().toISOString();
      if (row) {
        // Update
        db.run(
          `
          UPDATE blips
          SET lat = COALESCE(?, lat),
              lon = COALESCE(?, lon),
              status_message = COALESCE(?, status_message),
              updated_at = ?
          WHERE user_id = ?
        `,
          [lat ?? null, lon ?? null, status_message ?? null, now, userId],
          function (err2) {
            if (err2) {
              console.error("Blip update error:", err2);
              return res.status(500).json({ error: "failed to update blip" });
            }
            broadcastRadarUpdate(userId);
            res.json({ success: true });
          }
        );
      } else {
        // Insert
        db.run(
          `
          INSERT INTO blips (user_id, lat, lon, status_message, updated_at)
          VALUES (?, ?, ?, ?, ?)
        `,
          [userId, lat ?? null, lon ?? null, status_message ?? null, now],
          function (err2) {
            if (err2) {
              console.error("Blip insert error:", err2);
              return res.status(500).json({ error: "failed to create blip" });
            }
            broadcastRadarUpdate(userId);
            res.json({ success: true });
          }
        );
      }
    }
  );
});

// Radar: list visible users + their blips
app.get("/api/radar", authMiddleware, (req, res) => {
  db.all(
    `
    SELECT
      u.id,
      u.username,
      u.bio,
      u.avatar_base64,
      u.blip_color,
      u.visible,
      b.lat,
      b.lon,
      b.status_message,
      b.updated_at
    FROM users u
    LEFT JOIN blips b ON b.user_id = u.id
    WHERE u.visible = 1
  `,
    [],
    (err, rows) => {
      if (err) {
        console.error("Radar query error:", err);
        return res.status(500).json({ error: "failed to fetch radar" });
      }
      res.json(rows || []);
    }
  );
});

// --- CHAT ROUTES (REST for history) ---

// Get public messages (room_id = 'public')
app.get("/api/messages/public", authMiddleware, (req, res) => {
  db.all(
    `
    SELECT m.*, u.username
    FROM messages m
    JOIN users u ON u.id = m.from_user_id
    WHERE m.room_id = 'public'
    ORDER BY m.created_at ASC
    LIMIT 200
  `,
    [],
    (err, rows) => {
      if (err) {
        console.error("Public messages error:", err);
        return res.status(500).json({ error: "failed to fetch messages" });
      }
      res.json(rows || []);
    }
  );
});

// Get direct messages with one user
app.get("/api/dm/:userId", authMiddleware, (req, res) => {
  const me = req.user.id;
  const other = parseInt(req.params.userId, 10);

  db.all(
    `
    SELECT m.*, u.username as from_username
    FROM messages m
    JOIN users u ON u.id = m.from_user_id
    WHERE (m.from_user_id = ? AND m.to_user_id = ?)
       OR (m.from_user_id = ? AND m.to_user_id = ?)
    ORDER BY m.created_at ASC
    LIMIT 200
  `,
    [me, other, other, me],
    (err, rows) => {
      if (err) {
        console.error("DM messages error:", err);
        return res.status(500).json({ error: "failed to fetch dm messages" });
      }
      res.json(rows || []);
    }
  );
});

// --- EMOJI ROUTE (non-realtime version, WS handles live updates) ---

app.post("/api/emoji/send", authMiddleware, (req, res) => {
  const fromId = req.user.id;
  const { to_user_id, type } = req.body || {};
  if (!to_user_id || !type) {
    return res.status(400).json({ error: "to_user_id and type required" });
  }

  db.run(
    `
    INSERT INTO emoji_events (from_user_id, to_user_id, type)
    VALUES (?, ?, ?)
  `,
    [fromId, to_user_id, type],
    function (err) {
      if (err) {
        console.error("Emoji insert error:", err);
        return res.status(500).json({ error: "failed to send emoji" });
      }

      const payload = {
        type: "emoji",
        from_user_id: fromId,
        to_user_id,
        emoji_type: type,
        created_at: new Date().toISOString()
      };
      broadcastToUser(to_user_id, payload);
      res.json({ success: true });
    }
  );
});

// --- WEBSOCKET SERVER (ws) ---

const wss = new WebSocket.Server({ server });

/*
WebSocket protocol (JSON):
Client → server:
{
  "type": "auth",
  "token": "SESSION_TOKEN"
}

{
  "type": "public_message",
  "text": "hello world"
}

{
  "type": "dm",
  "to_user_id": 2,
  "text": "hey there"
}

{
  "type": "emoji",
  "to_user_id": 2,
  "emoji_type": "hug"
}

Server → client:
{
  "type": "public_message",
  "id": 1,
  "from_user_id": 1,
  "from_username": "Nova",
  "text": "hello",
  "created_at": "..."
}

{
  "type": "dm",
  ...
}

{
  "type": "emoji",
  ...
}

{
  "type": "radar_update",
  "user_id": 1
}
*/

const wsClients = new Map(); // ws -> { user, token }
const userSockets = new Map(); // userId -> Set<ws>

wss.on("connection", (ws) => {
  ws.isAlive = true;

  ws.on("pong", () => {
    ws.isAlive = true;
  });

  ws.on("message", async (msg) => {
    try {
      const data = JSON.parse(msg.toString());
      if (!data.type) return;

      if (data.type === "auth") {
        const user = await getUserByToken(data.token);
        if (!user) {
          ws.send(
            JSON.stringify({ type: "error", message: "invalid or expired token" })
          );
          return;
        }
        wsClients.set(ws, { user, token: data.token });
        if (!userSockets.has(user.id)) userSockets.set(user.id, new Set());
        userSockets.get(user.id).add(ws);

        ws.send(
          JSON.stringify({
            type: "auth_ok",
            user: {
              id: user.id,
              username: user.username,
              bio: user.bio,
              blip_color: user.blip_color,
              visible: !!user.visible
            }
          })
        );
        return;
      }

      const session = wsClients.get(ws);
      if (!session || !session.user) {
        ws.send(
          JSON.stringify({
            type: "error",
            message: "authenticate first with type=auth"
          })
        );
        return;
      }
      const me = session.user;

      if (data.type === "public_message") {
        const text = (data.text || "").toString().slice(0, 1000).trim();
        if (!text) return;

        db.run(
          `
          INSERT INTO messages (room_id, from_user_id, text)
          VALUES ('public', ?, ?)
        `,
          [me.id, text],
          function (err) {
            if (err) {
              console.error("WS public message insert error:", err);
              ws.send(
                JSON.stringify({ type: "error", message: "failed to save message" })
              );
              return;
            }
            const id = this.lastID;
            const payload = {
              type: "public_message",
              id,
              room_id: "public",
              from_user_id: me.id,
              from_username: me.username,
              text,
              created_at: new Date().toISOString()
            };
            broadcastAll(payload);
          }
        );
      } else if (data.type === "dm") {
        const toUserId = parseInt(data.to_user_id, 10);
        const text = (data.text || "").toString().slice(0, 1000).trim();
        if (!toUserId || !text) return;

        db.run(
          `
          INSERT INTO messages (from_user_id, to_user_id, text)
          VALUES (?, ?, ?)
        `,
          [me.id, toUserId, text],
          function (err) {
            if (err) {
              console.error("WS DM insert error:", err);
              ws.send(
                JSON.stringify({ type: "error", message: "failed to save dm" })
              );
              return;
            }
            const id = this.lastID;
            const payload = {
              type: "dm",
              id,
              from_user_id: me.id,
              from_username: me.username,
              to_user_id: toUserId,
              text,
              created_at: new Date().toISOString()
            };
            // send to both ends
            broadcastToUser(me.id, payload);
            broadcastToUser(toUserId, payload);
          }
        );
      } else if (data.type === "emoji") {
        const toUserId = parseInt(data.to_user_id, 10);
        const emoji_type = (data.emoji_type || "").toString();
        if (!toUserId || !emoji_type) return;

        db.run(
          `
          INSERT INTO emoji_events (from_user_id, to_user_id, type)
          VALUES (?, ?, ?)
        `,
          [me.id, toUserId, emoji_type],
          function (err) {
            if (err) {
              console.error("WS emoji insert error:", err);
              ws.send(
                JSON.stringify({ type: "error", message: "failed to save emoji" })
              );
              return;
            }
            const payload = {
              type: "emoji",
              from_user_id: me.id,
              to_user_id: toUserId,
              emoji_type,
              created_at: new Date().toISOString()
            };
            broadcastToUser(me.id, payload);
            broadcastToUser(toUserId, payload);
          }
        );
      }
    } catch (e) {
      console.error("WS message parse error:", e);
    }
  });

  ws.on("close", () => {
    const session = wsClients.get(ws);
    if (session && session.user) {
      const set = userSockets.get(session.user.id);
      if (set) {
        set.delete(ws);
        if (set.size === 0) userSockets.delete(session.user.id);
      }
    }
    wsClients.delete(ws);
  });
});

// WebSocket keepalive
setInterval(() => {
  wss.clients.forEach((ws) => {
    if (!ws.isAlive) return ws.terminate();
    ws.isAlive = false;
    ws.ping();
  });
}, 30000);

// --- WEBSOCKET BROADCAST HELPERS ---

function broadcastAll(payload) {
  const data = JSON.stringify(payload);
  wss.clients.forEach((client) => {
    if (client.readyState === WebSocket.OPEN) {
      client.send(data);
    }
  });
}

function broadcastToUser(userId, payload) {
  const set = userSockets.get(userId);
  if (!set) return;
  const data = JSON.stringify(payload);
  set.forEach((ws) => {
    if (ws.readyState === WebSocket.OPEN) {
      ws.send(data);
    }
  });
}

function broadcastRadarUpdate(userId) {
  const payload = {
    type: "radar_update",
    user_id: userId,
    at: new Date().toISOString()
  };
  broadcastAll(payload);
}

// --- FALLBACK TO index.html FOR ROOT ---
app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "index.html"));
});

// --- START SERVER ---
server.listen(PORT, () => {
  console.log(`Blip Radar server running at http://localhost:${PORT}`);
});
