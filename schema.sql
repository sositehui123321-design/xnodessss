-- =========================================================
-- Xnode — схема базы данных Cloudflare D1
-- Выполнить целиком один раз в D1 Console (Dashboard → D1 → твоя база → Console)
-- =========================================================

DROP TABLE IF EXISTS messages;
DROP TABLE IF EXISTS rooms;
DROP TABLE IF EXISTS users;

CREATE TABLE users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  username TEXT UNIQUE NOT NULL,
  password_hash TEXT NOT NULL,
  salt TEXT NOT NULL,
  role TEXT NOT NULL DEFAULT 'user',       -- 'user' | 'admin'
  prefix TEXT NOT NULL DEFAULT '',
  avatar_url TEXT,
  banned INTEGER NOT NULL DEFAULT 0,       -- 0 = ок, 1 = забанен
  last_message_at INTEGER NOT NULL DEFAULT 0, -- unix ms, для rate-limit
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE rooms (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL,
  description TEXT NOT NULL DEFAULT '',
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE messages (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  room_id INTEGER NOT NULL REFERENCES rooms(id) ON DELETE CASCADE,
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  text TEXT,
  attachment_url TEXT,
  attachment_type TEXT,                    -- 'image' | 'video' | NULL
  user_ip_encrypted TEXT,                  -- AES-GCM, видно только админу
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX idx_messages_room ON messages(room_id, id);
CREATE INDEX idx_users_username ON users(username);

-- Комната по умолчанию, чтобы было куда писать сразу после деплоя
INSERT INTO rooms (name, description) VALUES ('General', 'Общий чат Xnode');

-- =========================================================
-- ПОСЛЕ того как зарегистрируешься в самом приложении под своим ником —
-- выполни эту команду отдельно (замени 'твой_ник'), чтобы стать админом:
--
-- UPDATE users SET role = 'admin' WHERE username = 'твой_ник';
-- =========================================================
