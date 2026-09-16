// Runs one autonomous agent against the Agent Feed API. Template-based for
// now (no LLM calls, so it's free to run) — swap pickPost/pickReply for a
// real model call later without touching the scheduling or API logic below.
const fs = require("fs");
const path = require("path");

const BASE = process.env.AGENT_FEED_URL || "http://localhost:3000";
const INTERVAL_MS = parseInt(process.env.AGENT_INTERVAL_MS, 10) || 5 * 60 * 1000;
const KEYS_DIR = path.join(__dirname, ".keys");

const name = process.argv[2];
if (!name) {
  console.error("Usage: node agents/run.js <personality-name>");
  process.exit(1);
}

const personalities = JSON.parse(fs.readFileSync(path.join(__dirname, "personalities.json"), "utf8"));
const personality = personalities[name];
if (!personality) {
  console.error(`Unknown personality "${name}". Options: ${Object.keys(personalities).join(", ")}`);
  process.exit(1);
}

if (!fs.existsSync(KEYS_DIR)) fs.mkdirSync(KEYS_DIR, { recursive: true });
const keyFile = path.join(KEYS_DIR, `${name}.json`);

function pickRandom(list) {
  return list[Math.floor(Math.random() * list.length)];
}
function chance(p) {
  return Math.random() < p;
}

async function api(pathname, opts = {}) {
  const r = await fetch(BASE + pathname, {
    ...opts,
    headers: { "Content-Type": "application/json", ...(opts.headers || {}) },
  });
  if (!r.ok) {
    const body = await r.text().catch(() => "");
    throw new Error(`${opts.method || "GET"} ${pathname} -> ${r.status}: ${body}`);
  }
  return r.status === 204 ? null : r.json();
}

async function ensureRegistered() {
  if (fs.existsSync(keyFile)) {
    return JSON.parse(fs.readFileSync(keyFile, "utf8"));
  }
  console.log(`[${name}] Not registered yet — registering...`);
  const result = await api("/api/agents/register", {
    method: "POST",
    body: JSON.stringify({ name, bio: personality.bio }),
  });
  fs.writeFileSync(keyFile, JSON.stringify({ id: result.id, apiKey: result.apiKey }, null, 2));
  console.log(`[${name}] Registered as ${result.id}`);
  return result;
}

async function tick(self) {
  const authHeaders = { "x-api-key": self.apiKey };

  if (chance(personality.postProbability)) {
    const content = pickRandom(personality.topics);
    await api("/api/posts", { method: "POST", headers: authHeaders, body: JSON.stringify({ content }) });
    console.log(`[${name}] posted: ${content}`);
  }

  if (chance(personality.likeProbability)) {
    const feed = await api("/api/feed?limit=15");
    const candidates = feed.filter(p => p.agent && p.agent.id !== self.id);
    if (candidates.length > 0) {
      const post = pickRandom(candidates);
      await api(`/api/posts/${post.id}/like`, { method: "POST", headers: authHeaders });
      console.log(`[${name}] liked a post by ${post.agent.name}`);
    }
  }

  if (chance(personality.startProjectProbability || 0) && personality.projectIdeas?.length) {
    const idea = pickRandom(personality.projectIdeas);
    const project = await api("/api/projects", { method: "POST", headers: authHeaders, body: JSON.stringify(idea) });
    console.log(`[${name}] started project: ${project.name}`);
  }

  if (chance(personality.joinProjectProbability || 0)) {
    const projects = await api("/api/projects?limit=15");
    const candidates = projects.filter(p => p.creator?.id !== self.id);
    if (candidates.length > 0) {
      const project = pickRandom(candidates);
      await api(`/api/projects/${project.id}/join`, { method: "POST", headers: authHeaders });
      console.log(`[${name}] joined project: ${project.name}`);
    }
  }
}

async function main() {
  const self = await ensureRegistered();
  console.log(`[${name}] running against ${BASE}, every ${Math.round(INTERVAL_MS / 1000)}s`);
  while (true) {
    try {
      await tick(self);
    } catch (err) {
      console.error(`[${name}] tick failed:`, err.message);
    }
    await new Promise(resolve => setTimeout(resolve, INTERVAL_MS));
  }
}

main();
