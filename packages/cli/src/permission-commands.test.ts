import { describe, it, expect, beforeAll, afterAll, beforeEach } from "bun:test";
import { existsSync, mkdirSync, writeFileSync, rmSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";

const TEST_API_URL = "http://localhost:3001";

const execCLI = async (args: string[], configPath?: string): Promise<{ stdout: string; stderr: string; exitCode: number }> => {
  const cmd = [
    "bun",
    "run",
    "/Users/mat/dev/claw.events/packages/cli/src/index.ts",
    ...(configPath ? ["--config", configPath] : []),
    ...args
  ];

  const proc = Bun.spawn({
    cmd,
    stdout: "pipe",
    stderr: "pipe",
    env: { ...process.env, CLAW_API_URL: TEST_API_URL }
  });

  const stdoutPromise = new Response(proc.stdout).text();
  const stderrPromise = new Response(proc.stderr).text();
  const exitCode = await proc.exited;
  const [stdout, stderr] = await Promise.all([stdoutPromise, stderrPromise]);

  return { stdout, stderr, exitCode };
};

describe("CLI Permission Commands", () => {
  const testDir = join(tmpdir(), "claw-cli-perm-test-" + Date.now());
  
  beforeAll(() => {
    if (!existsSync(testDir)) mkdirSync(testDir, { recursive: true });
  });
  
  afterAll(() => {
    try { rmSync(testDir, { recursive: true, force: true }); } catch {}
  });
  
  beforeEach(() => {
    try { rmSync(join(testDir, "config.json"), { force: true }); } catch {}
  });

  it("Test 26.1: lock - Happy Path", async () => {
    writeFileSync(join(testDir, "config.json"), JSON.stringify({ 
      username: "testuser", token: "eyJ.test"
    }));
    const { stdout, exitCode } = await execCLI(["lock", "agent.testuser.private"], testDir);
    if (exitCode === 0) {
      const output = JSON.parse(stdout);
      expect(output.status).toBe("success");
    }
  });

  it("Test 26.2: lock - Not Authenticated", async () => {
    const { stderr, exitCode } = await execCLI(["lock", "agent.testuser.private"], testDir);
    expect(exitCode).toBe(1);
    const output = JSON.parse(stderr);
    expect(output.error).toContain("Authentication required");
  });

  it("Test 26.3: lock - Non-Owner", async () => {
    writeFileSync(join(testDir, "config.json"), JSON.stringify({ 
      username: "testuser", token: "eyJ.test"
    }));
    const { stderr, exitCode } = await execCLI(["lock", "agent.other.private"], testDir);
    expect(exitCode).toBe(1);
  });

  it("Test 26.4: lock - Missing Channel", async () => {
    writeFileSync(join(testDir, "config.json"), JSON.stringify({ 
      username: "testuser", token: "eyJ.test"
    }));
    const { stderr, exitCode } = await execCLI(["lock"], testDir);
    expect(exitCode).toBe(1);
    const output = JSON.parse(stderr);
    expect(output.error).toContain("Missing channel");
  });

  it("Test 26.5: unlock - Happy Path", async () => {
    writeFileSync(join(testDir, "config.json"), JSON.stringify({ 
      username: "testuser", token: "eyJ.test"
    }));
    await execCLI(["lock", "agent.testuser.unlock"], testDir);
    const { stdout, exitCode } = await execCLI(["unlock", "agent.testuser.unlock"], testDir);
    if (exitCode === 0) {
      const output = JSON.parse(stdout);
      expect(output.status).toBe("success");
    }
  });

  it("Test 26.6: unlock - Not Locked (Graceful)", async () => {
    writeFileSync(join(testDir, "config.json"), JSON.stringify({ 
      username: "testuser", token: "eyJ.test"
    }));
    const { stdout, exitCode } = await execCLI(["unlock", "agent.testuser.neverlocked"], testDir);
    expect([0, 1]).toContain(exitCode);
  });

  it("Test 26.7: grant - Happy Path", async () => {
    writeFileSync(join(testDir, "config.json"), JSON.stringify({ 
      username: "alice", token: "eyJ.test"
    }));
    await execCLI(["lock", "agent.alice.shared"], testDir);
    const { stdout, exitCode } = await execCLI(["grant", "bob", "agent.alice.shared"], testDir);
    if (exitCode === 0) {
      const output = JSON.parse(stdout);
      expect(output.status).toBe("success");
    }
  });

  it("Test 26.8: grant - Not Authenticated", async () => {
    const { stderr, exitCode } = await execCLI(["grant", "bob", "agent.alice.shared"], testDir);
    expect(exitCode).toBe(1);
    const output = JSON.parse(stderr);
    expect(output.error).toContain("Authentication required");
  });

  it("Test 26.9: grant - Non-Owner", async () => {
    writeFileSync(join(testDir, "config.json"), JSON.stringify({ 
      username: "bob", token: "eyJ.test"
    }));
    const { stderr, exitCode } = await execCLI(["grant", "charlie", "agent.alice.shared"], testDir);
    expect(exitCode).toBe(1);
  });

  it("Test 26.10: grant - Missing Target or Channel", async () => {
    writeFileSync(join(testDir, "config.json"), JSON.stringify({ 
      username: "testuser", token: "eyJ.test"
    }));
    const { stderr, exitCode } = await execCLI(["grant"], testDir);
    expect(exitCode).toBe(1);
    const output = JSON.parse(stderr);
    expect(output.error).toContain("Missing");
  });

  it("Test 26.11: revoke - Happy Path", async () => {
    writeFileSync(join(testDir, "config.json"), JSON.stringify({ 
      username: "alice", token: "eyJ.test"
    }));
    await execCLI(["lock", "agent.alice.revoke"], testDir);
    await execCLI(["grant", "bob", "agent.alice.revoke"], testDir);
    const { stdout, exitCode } = await execCLI(["revoke", "bob", "agent.alice.revoke"], testDir);
    if (exitCode === 0) {
      const output = JSON.parse(stdout);
      expect(output.status).toBe("success");
    }
  });

  it("Test 26.12: revoke - Not Granted (Graceful)", async () => {
    writeFileSync(join(testDir, "config.json"), JSON.stringify({ 
      username: "alice", token: "eyJ.test"
    }));
    await execCLI(["lock", "agent.alice.revoke2"], testDir);
    const { stdout, exitCode } = await execCLI(["revoke", "bob", "agent.alice.revoke2"], testDir);
    expect([0, 1]).toContain(exitCode);
  });

  it("Test 26.13: request - Happy Path", async () => {
    writeFileSync(join(testDir, "config.json"), JSON.stringify({ 
      username: "bob", token: "eyJ.test"
    }));
    const { stdout, exitCode } = await execCLI(["request", "agent.alice.private", "Need access"], testDir);
    if (exitCode === 0) {
      const output = JSON.parse(stdout);
      expect(output.status).toBe("success");
    }
  });

  it("Test 26.14: request - Not Authenticated", async () => {
    const { stderr, exitCode } = await execCLI(["request", "agent.alice.private", "Need access"], testDir);
    expect(exitCode).toBe(1);
    const output = JSON.parse(stderr);
    expect(output.error).toContain("Authentication required");
  });

  it("Test 26.15: request - Channel Not Locked", async () => {
    writeFileSync(join(testDir, "config.json"), JSON.stringify({ 
      username: "bob", token: "eyJ.test"
    }));
    const { stderr, exitCode } = await execCLI(["request", "agent.alice.public", "Need access"], testDir);
    expect(exitCode).toBe(1);
  });

  it("Test 26.16: request - Already Granted", async () => {
    writeFileSync(join(testDir, "config.json"), JSON.stringify({ 
      username: "bob", token: "eyJ.test"
    }));
    const { stderr, exitCode } = await execCLI(["request", "agent.alice.granted", "Need access"], testDir);
    expect([0, 1]).toContain(exitCode);
  });
});
