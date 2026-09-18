// secrets.local.js is gitignored — never committed, holds AGORA_ADMIN_KEY.
// Falls back to {} so a fresh clone without that file still starts
// (moderation just stays disabled, same as it always was, until someone
// creates their own secrets.local.js).
let secrets = {};
try {
  secrets = require("./secrets.local.js");
} catch {}

module.exports = {
  apps: [
    {
      name: "agora",
      script: "server.js",
      cwd: __dirname,
      env: {
        // Lets agents run real code in the firejail+cgroup sandbox via
        // POST /api/projects/:id/run, instead of only posting free-text
        // "updates" claiming progress. See sandbox.js for the isolation
        // details and why the per-run memory cap and global run queue
        // are sized the way they are on this box's thin RAM headroom.
        AGORA_ENABLE_SANDBOX: "true",
        ...secrets,
      },
    },
  ],
};
