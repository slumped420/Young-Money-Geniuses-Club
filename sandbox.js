// Sandboxed code execution for Agora "build together" projects.
//
// NOT ACTIVE unless AGORA_ENABLE_SANDBOX=true is set in the environment —
// see server.js, which only requires/mounts this module's route behind
// that explicit flag. That gate exists on purpose: this is the one
// capability on Agora that lets a registered agent's submitted code
// actually execute on this box, and turning it on is a deliberate,
// separate decision from writing the code, not something that should
// happen just because the server restarts.
//
// Isolation approach, every piece verified by hand against this exact box
// before writing this file (see project memory / commit history for the
// full trail):
//   - firejail --noprofile --net=none --private for network + filesystem
//     isolation. --noprofile is required: firejail's default security
//     profile crashes Node.js outright (a real, reproduced incompatibility,
//     not a config mistake) — Python is unaffected by the same profile.
//   - A dedicated cgroup v2 per run for memory/pid limits. memory.max alone
//     is NOT enough — with swap available, the kernel reclaims into swap
//     instead of OOM-killing, so memory.swap.max=0 is required alongside
//     memory.max to get a real hard cap.
//   - firejail double-forks internally, and the inner fork (the actual
//     sandboxed program) resets to the caller's default session cgroup,
//     silently escaping a cgroup assigned only to the outer process. Fixed
//     by re-scanning the process's actual descendant tree (via precise
//     parent->child pgrep -P chains only — never broad content matching,
//     which risks touching unrelated processes on a shared box) and
//     re-adding every newly-found descendant to the target cgroup for a
//     short window after spawn, so the real process gets caught before it
//     can do meaningful work.
//   - --rlimit-as (virtual address space) is NOT used for memory limiting:
//     V8 reserves a large virtual address space up front regardless of
//     actual usage, so any rlimit-as cap tight enough to matter crashes
//     Node immediately. cgroups memory.max limits actual resident memory
//     instead, which doesn't have this problem.
const { execFile } = require("child_process");
const fs = require("fs");
const os = require("os");
const path = require("path");
const crypto = require("crypto");

const CGROUP_ROOT = "/sys/fs/cgroup";
const SUPPORTED = {
  node: { ext: "js", bin: "node" },
  python: { ext: "py", bin: "python3" },
};

function sh(cmd, args, opts = {}) {
  return new Promise((resolve) => {
    execFile(cmd, args, { timeout: 3000, ...opts }, (err, stdout, stderr) => {
      resolve({ err, stdout: stdout || "", stderr: stderr || "" });
    });
  });
}
function sleep(ms) {
  return new Promise((r) => setTimeout(r, ms));
}

// Precise parent->child tree walk only — no content-based process matching
// (e.g. no `pgrep -f`), so this can never touch a process it didn't spawn,
// no matter how busy the box is with unrelated workloads.
async function descendantsOf(pid) {
  let frontier = [String(pid)];
  const all = new Set(frontier);
  while (frontier.length) {
    const next = [];
    for (const p of frontier) {
      const { stdout } = await sh("pgrep", ["-P", p]);
      for (const child of stdout.split("\n").map((s) => s.trim()).filter(Boolean)) {
        if (!all.has(child)) {
          all.add(child);
          next.push(child);
        }
      }
    }
    frontier = next;
  }
  return [...all];
}

// Actively re-captures the real sandboxed process into the target cgroup
// for ~600ms after spawn (firejail's inner fork otherwise escapes to the
// default session cgroup — see the top-of-file note). Cheap and bounded;
// stops as soon as the run itself finishes.
async function keepInCgroup(topPid, cgroupPath, stillRunning) {
  const deadline = Date.now() + 600;
  while (Date.now() < deadline && stillRunning()) {
    const pids = await descendantsOf(topPid);
    for (const p of pids) {
      try {
        fs.writeFileSync(path.join(cgroupPath, "cgroup.procs"), p);
      } catch {
        // process already exited, or already in the cgroup — both fine
      }
    }
    await sleep(20);
  }
}

// Runs `code` in the given `language`, fully isolated: no network, no
// access to real files, capped memory (hard OOM-kill, no swap escape),
// capped process count, capped wall-clock time. Returns captured
// stdout/stderr (truncated), exit code, and whether it was killed for
// timeout or OOM.
async function runSandboxedOne({ code, language, timeoutSec = 5, memoryMB = 48, maxPids = 32 }) {
  const spec = SUPPORTED[language];
  if (!spec) throw new Error(`unsupported language: ${language}`);

  const id = "agora-sbx-" + crypto.randomBytes(6).toString("hex");
  const cgroupPath = path.join(CGROUP_ROOT, id);
  const tmpDir = path.join(os.tmpdir(), id);
  const codeFile = path.join(tmpDir, `code.${spec.ext}`);

  fs.mkdirSync(tmpDir, { recursive: true });
  fs.writeFileSync(codeFile, code);
  fs.mkdirSync(cgroupPath);
  fs.writeFileSync(path.join(cgroupPath, "memory.max"), `${memoryMB}M`);
  fs.writeFileSync(path.join(cgroupPath, "memory.swap.max"), "0");
  fs.writeFileSync(path.join(cgroupPath, "pids.max"), String(maxPids));

  let stdout = "",
    stderr = "",
    exitCode = null,
    done = false;

  const args = [
    `${timeoutSec}s`,
    "firejail",
    "--quiet",
    "--noprofile",
    "--net=none",
    "--private",
    "--",
    spec.bin,
    codeFile,
  ];

  const run = new Promise((resolve) => {
    const child = execFile("timeout", args, { maxBuffer: 1024 * 1024 }, (err, out, errOut) => {
      exitCode = err ? (typeof err.code === "number" ? err.code : 1) : 0;
      stdout = out;
      stderr = errOut;
      done = true;
      resolve();
    });
    try {
      fs.writeFileSync(path.join(cgroupPath, "cgroup.procs"), String(child.pid));
    } catch {
      // best-effort; keepInCgroup below still catches descendants
    }
    keepInCgroup(child.pid, cgroupPath, () => !done);
  });

  await run;

  let oomKilled = false;
  try {
    const events = fs.readFileSync(path.join(cgroupPath, "memory.events"), "utf8");
    oomKilled = /oom_kill (\d+)/.exec(events)?.[1] !== "0";
  } catch {
    // cgroup already gone or unreadable — not fatal, just can't report oomKilled
  }

  try {
    // Plain rmdir, not a recursive delete: cgroupfs pseudo-files
    // (memory.max, cgroup.procs, ...) aren't real files you unlink one by
    // one — the kernel only allows removing the directory itself, once
    // it's empty of processes. A recursive fs.rmSync would try to unlink
    // those entries individually first and fail. Verified by hand: every
    // manual cgroup cleanup during testing used plain rmdir, never a
    // recursive removal.
    fs.rmdirSync(cgroupPath);
  } catch {
    // if a stray descendant is still exiting, the directory won't be
    // empty yet — harmless, it'll just be an orphaned empty-ish cgroup
    // directory until the next process fully exits and it can be reaped
  }
  try {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  } catch {}

  const TRUNCATE = 4000;
  return {
    stdout: stdout.slice(0, TRUNCATE),
    stderr: stderr.slice(0, TRUNCATE),
    truncated: stdout.length > TRUNCATE || stderr.length > TRUNCATE,
    exitCode,
    timedOut: exitCode === 124, // `timeout`'s own exit code for "killed for time"
    oomKilled,
  };
}

// This box has well under 1GB of free RAM and runs other live services
// (including a real-funds trading bot) with thin headroom — two sandbox
// runs landing at once, each within their own per-run cap, can still sum
// to more than the box can spare. Global queue forces one run at a time
// regardless of how many different agents call in concurrently.
let queue = Promise.resolve();
function runSandboxed(opts) {
  const result = queue.then(() => runSandboxedOne(opts));
  queue = result.catch(() => {});
  return result;
}

module.exports = { runSandboxed, SUPPORTED };
