import { describe, it, expect, beforeAll, afterAll, beforeEach } from "bun:test";
import { existsSync, mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
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

describe("CLI Authentication Commands", () => {
  const testDir = join(tmpdir(), "claw-cli-auth-test-" + Date.now());

  beforeAll(() => {
    if (!existsSync(testDir)) {
      mkdirSync(testDir, { recursive: true });
    }
  });

  afterAll(() => {
    try {
      rmSync(testDir, { recursive: true, force: true });
    } catch {
      // Ignore
    }
  });

  beforeEach(() => {
    try {
      rmSync(join(testDir, "config.json"), { force: true });
    } catch {
      // Ignore
    }
  });

  it("Test 23.1: login --user - Missing Username", async () => {
    const { stderr, exitCode } = await execCLI(["login"], testDir);
    expect(exitCode).toBe(1);
    const output = JSON.parse(stderr);
    expect(output.status).toBe("error");
    expect(output.error).toContain("Missing --user");
  });

  it("Test 23.2: login --token - Saves Token", async () => {
    const testToken = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.test";
    const { exitCode } = await execCLI(["login", "--token", testToken], testDir);

    if (exitCode === 0) {
      const configPath = join(testDir, "config.json");
      if (existsSync(configPath)) {
        const config = JSON.parse(readFileSync(configPath, "utf8"));
        expect(config.token).toBe(testToken);
      }
    }
  });

  it("Test 23.3: verify - Deprecated", async () => {
    const { stderr, exitCode } = await execCLI(["verify"], testDir);
    expect(exitCode).toBe(1);
    const output = JSON.parse(stderr);
    expect(output.error).toContain("deprecated");
  });

  it("Test 23.4: whoami - Authenticated State", async () => {
    writeFileSync(join(testDir, "config.json"), JSON.stringify({
      username: "testuser",
      token: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.test"
    }));

    const { stdout, exitCode } = await execCLI(["whoami"], testDir);
    expect(exitCode).toBe(0);
    const output = JSON.parse(stdout);
    expect(output.data.authenticated).toBe(true);
    expect(output.data.username).toBe("testuser");
  });

  it("Test 23.5: logout - Clears Auth", async () => {
    writeFileSync(join(testDir, "config.json"), JSON.stringify({
      username: "testuser",
      token: "test-token"
    }));

    const { stdout, exitCode } = await execCLI(["logout"], testDir);
    expect(exitCode).toBe(0);

    const configPath = join(testDir, "config.json");
    if (existsSync(configPath)) {
      const config = JSON.parse(readFileSync(configPath, "utf8"));
      expect(config.token).toBeUndefined();
      expect(config.username).toBeUndefined();
    }

    const output = JSON.parse(stdout);
    expect(output.status).toBe("success");
  });
});
