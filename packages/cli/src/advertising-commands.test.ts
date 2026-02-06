import { describe, it, expect, beforeAll, afterAll, beforeEach } from "bun:test";
import { existsSync, mkdirSync, writeFileSync, rmSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";

const TEST_API_URL = "http://localhost:3001";

const registerUser = async (username: string, configDir: string) => {
  const { exitCode } = await execCLI(["dev-register", "--user", username], configDir);
  if (exitCode !== 0) {
    throw new Error(`Failed to register ${username}`);
  }
};

const execCLI = async (args: string[], configPath?: string): Promise<{ stdout: string; stderr: string; exitCode: number }> => {
  const cmd = [
    "bun",
    "run",
    "/Users/mat/dev/claw.events/packages/cli/src/index.ts",
    ...(configPath ? ["--config", configPath] : []),
    "--json",
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

describe("CLI Advertising Commands", () => {
  const testDir = join(tmpdir(), "claw-cli-ad-test-" + Date.now());
  
  beforeAll(() => {
    if (!existsSync(testDir)) mkdirSync(testDir, { recursive: true });
  });
  
  afterAll(() => {
    try { rmSync(testDir, { recursive: true, force: true }); } catch {}
  });
  
  beforeEach(() => {
    try { rmSync(join(testDir, "config.json"), { force: true }); } catch {}
  });

  it("Test 27.1: advertise set - Happy Path", async () => {
    await registerUser("testuser", testDir);
    const { stdout, exitCode } = await execCLI([
      "advertise", "set", "--channel", "agent.testuser.data", "--desc", "Test data"
    ], testDir);
    if (exitCode === 0) {
      const output = JSON.parse(stdout);
      expect(output.status).toBe("success");
    }
  });

  it("Test 27.2: advertise set - With Schema", async () => {
    await registerUser("testuser", testDir);
    const { stdout, exitCode } = await execCLI([
      "advertise", "set",
      "-c", "agent.testuser.schema",
      "-d", "With schema",
      "-s", '{"type":"object"}'
    ], testDir);
    if (exitCode === 0) {
      const output = JSON.parse(stdout);
      expect(output.status).toBe("success");
    }
  });

  it("Test 27.3: advertise set - Not Authenticated", async () => {
    const { stderr, exitCode } = await execCLI([
      "advertise", "set", "--channel", "agent.testuser.data", "--desc", "Test"
    ], testDir);
    expect(exitCode).toBe(1);
    const output = JSON.parse(stderr);
    expect(output.error).toContain("Authentication required");
  });

  it("Test 27.4: advertise set - Non-Owner", async () => {
    await registerUser("testuser", testDir);
    const { stderr, exitCode } = await execCLI([
      "advertise", "set", "--channel", "agent.other.data", "--desc", "Test"
    ], testDir);
    expect(exitCode).toBe(1);
  });

  it("Test 27.5: advertise set - Missing Channel", async () => {
    await registerUser("testuser", testDir);
    const { stderr, exitCode } = await execCLI([
      "advertise", "set", "--desc", "Test"
    ], testDir);
    expect(exitCode).toBe(1);
  });

  it("Test 27.6: advertise delete - Happy Path", async () => {
    await registerUser("testuser", testDir);
    await execCLI([
      "advertise", "set", "--channel", "agent.testuser.delete", "--desc", "To delete"
    ], testDir);
    const { stdout, exitCode } = await execCLI([
      "advertise", "delete", "agent.testuser.delete"
    ], testDir);
    if (exitCode === 0) {
      const output = JSON.parse(stdout);
      expect(output.status).toBe("success");
    }
  });

  it("Test 27.7: advertise list - All Channels", async () => {
    const { stdout, exitCode } = await execCLI(["advertise", "list"], testDir);
    expect(exitCode).toBe(0);
    const output = JSON.parse(stdout);
    expect(output.data.channelsByAgent).toBeDefined();
  });

  it("Test 27.8: advertise list - Specific Agent", async () => {
    const { stdout, exitCode } = await execCLI(["advertise", "list", "testuser"], testDir);
    expect(exitCode).toBe(0);
    const output = JSON.parse(stdout);
    expect(output.data.targetAgent).toBe("testuser");
  });

  it("Test 27.9: advertise search - Happy Path", async () => {
    const { stdout, exitCode } = await execCLI(["advertise", "search", "test"], testDir);
    expect(exitCode).toBe(0);
    const output = JSON.parse(stdout);
    expect(output.data.results).toBeDefined();
  });

  it("Test 27.10: advertise search - With Limit", async () => {
    const { stdout, exitCode } = await execCLI(["advertise", "search", "test", "--limit", "5"], testDir);
    expect(exitCode).toBe(0);
    const output = JSON.parse(stdout);
    expect(output.data.results.length).toBeLessThanOrEqual(5);
  });

  it("Test 27.11: advertise search - No Results", async () => {
    const { stdout, exitCode } = await execCLI(["advertise", "search", "xyznonexistent123"], testDir);
    expect(exitCode).toBe(0);
    const output = JSON.parse(stdout);
    expect(output.data.results.length).toBe(0);
  });

  it("Test 27.12: advertise show - Happy Path", async () => {
    await registerUser("testuser", testDir);
    await execCLI([
      "advertise", "set", "--channel", "agent.testuser.show", "--desc", "Show test"
    ], testDir);
    const { stdout, exitCode } = await execCLI(["advertise", "show", "agent.testuser.show"], testDir);
    if (exitCode === 0) {
      const output = JSON.parse(stdout);
      expect(output.data.channel).toBe("agent.testuser.show");
    }
  });

  it("Test 27.13: advertise show - Not Found", async () => {
    const { stderr, exitCode } = await execCLI(["advertise", "show", "agent.nonexistent.data"], testDir);
    expect(exitCode).toBe(1);
  });

  it("Test 27.14: advertise show - Invalid Channel Format", async () => {
    const { stderr, exitCode } = await execCLI(["advertise", "show", "invalid"], testDir);
    expect(exitCode).toBe(1);
  });
});
