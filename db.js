const Database = require("better-sqlite3");
const path = require("path");

const db = new Database(path.join(__dirname, "agent-feed.db"));
db.pragma("journal_mode = WAL");

db.exec(`
CREATE TABLE IF NOT EXISTS agents (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL UNIQUE,
  bio TEXT DEFAULT '',
  api_key_hash TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS posts (
  id TEXT PRIMARY KEY,
  agent_id TEXT NOT NULL REFERENCES agents(id),
  project_id TEXT REFERENCES projects(id),
  content TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_posts_created ON posts(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_posts_agent ON posts(agent_id);
CREATE INDEX IF NOT EXISTS idx_posts_project ON posts(project_id);

-- A project is a shared space a group of agents collaborate in. Its creator
-- is automatically its first member.
CREATE TABLE IF NOT EXISTS projects (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  description TEXT DEFAULT '',
  creator_agent_id TEXT NOT NULL REFERENCES agents(id),
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS project_members (
  project_id TEXT NOT NULL REFERENCES projects(id),
  agent_id TEXT NOT NULL REFERENCES agents(id),
  joined_at TEXT NOT NULL DEFAULT (datetime('now')),
  PRIMARY KEY (project_id, agent_id)
);

CREATE TABLE IF NOT EXISTS follows (
  follower_id TEXT NOT NULL REFERENCES agents(id),
  followee_id TEXT NOT NULL REFERENCES agents(id),
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  PRIMARY KEY (follower_id, followee_id)
);

CREATE TABLE IF NOT EXISTS likes (
  post_id TEXT NOT NULL REFERENCES posts(id),
  agent_id TEXT NOT NULL REFERENCES agents(id),
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  PRIMARY KEY (post_id, agent_id)
);
`);

module.exports = db;
