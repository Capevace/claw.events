import { describe, it, expect, beforeAll, afterAll, beforeEach } from "bun:test";
import { existsSync, mkdirSync, writeFileSync, readFileSync, rmSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";

// Test helpers
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
    env: { ...process.env }
  });

  const stdoutPromise = new Response(proc.stdout).text();
  const stderrPromise = new Response(proc.stderr).text();
  const exitCode = await proc.exited;
  const [stdout, stderr] = await Promise.all([stdoutPromise, stderrPromise]);

  return { stdout, stderr, exitCode };
};

describe("CLI Global Options Tests", () => {
  const testDir = join(tmpdir(), "claw-cli-test-" + Date.now());
  
  beforeAll(() => {
    if (!existsSync(testDir)) {
      mkdirSync(testDir, { recursive: true });
    }
  });
  
  afterAll(() => {
    // Cleanup
    try {
      rmSync(testDir, { recursive: true, force: true });
    } catch {
      // Ignore cleanup errors
    }
  });
  
  beforeEach(() => {
    // Clean test dir before each test
    const files = ["config.json", "custom.json"];
    for (const file of files) {
      try {
        rmSync(join(testDir, file), { force: true });
      } catch {
        // Ignore
      }
    }
  });

  describe("Test 22.1: --config with Custom File", () => {
    it("should use custom config file path", async () => {
      const customConfig = join(testDir, "custom.json");
      writeFileSync(customConfig, JSON.stringify({ serverUrl: "http://custom.example.com" }));
      
      const { stdout } = await execCLI(["config", "--show"], customConfig);
      const output = JSON.parse(stdout);
      
      expect(output.data.serverUrl).toBe("http://custom.example.com");
    });
  });

  describe("Test 22.2: --config with Custom Directory", () => {
    it("should use config.json in custom directory", async () => {
      const customDir = join(testDir, "customdir");
      mkdirSync(customDir, { recursive: true });
      writeFileSync(join(customDir, "config.json"), JSON.stringify({ serverUrl: "http://dir.example.com" }));
      
      const { stdout } = await execCLI(["config", "--show"], customDir);
      const output = JSON.parse(stdout);
      
      expect(output.data.serverUrl).toBe("http://dir.example.com");
    });
  });

  describe("Test 22.3: --config Creates Directory", () => {
    it("should create directory if it doesn't exist", async () => {
      const newDir = join(testDir, "newdir", "subdir");
      
      await execCLI(["config", "--server", "http://test.example.com"], newDir);
      
      // Directory should be created
      expect(existsSync(newDir)).toBe(true);
      
      // Config file should be created
      const configPath = join(newDir, "config.json");
      expect(existsSync(configPath)).toBe(true);
      
      const config = JSON.parse(readFileSync(configPath, "utf8"));
      expect(config.serverUrl).toBe("http://test.example.com");
    });
  });

  describe("Test 22.4: --config Falls Back to Default", () => {
    it("should use default path when no --config specified", async () => {
      const { stdout } = await execCLI(["config", "--show"]);
      const output = JSON.parse(stdout);
      
      // Should show default config path
      expect(output.data.configPath).toContain(".claw.events");
    });
  });

  describe("Test 22.5: --server Overrides Config", () => {
    it("should override config server with --server flag", async () => {
      const config = join(testDir, "config.json");
      writeFileSync(config, JSON.stringify({ serverUrl: "http://config.example.com" }));
      
      const { stdout } = await execCLI(["--server", "http://override.example.com", "config", "--show"], config);
      const output = JSON.parse(stdout);
      
      expect(output.data.serverUrl).toBe("http://override.example.com");
      expect(output.data.globalOptions.serverUrl).toBe("http://override.example.com");
    });
  });

  describe("Test 22.6: --server Derives WS URL (HTTPS)", () => {
    it("should derive wss URL from https server", async () => {
      const { stdout } = await execCLI(["--server", "https://example.com", "config", "--show"]);
      const output = JSON.parse(stdout);
      
      expect(output.data.wsUrl).toBe("wss://example.com/connection/websocket");
    });
  });

  describe("Test 22.7: --server Derives WS URL (HTTP)", () => {
    it("should derive ws URL from http server", async () => {
      const { stdout } = await execCLI(["--server", "http://localhost:8080", "config", "--show"]);
      const output = JSON.parse(stdout);
      
      expect(output.data.wsUrl).toBe("ws://localhost:8080/connection/websocket");
    });
  });

  describe("Test 22.8: --token Overrides Config", () => {
    it("should override config token with --token flag", async () => {
      const config = join(testDir, "config.json");
      writeFileSync(config, JSON.stringify({ token: "config-token" }));
      
      const { stdout } = await execCLI(["--token", "override-token", "whoami"], config);
      const output = JSON.parse(stdout);
      
      expect(output.data.globalOptions.hasToken).toBe(true);
      expect(output.data.authenticated).toBe(true);
    });
  });

  describe("Test 22.9: --token Not Saved to Config", () => {
    it("should not save --token to config file", async () => {
      const config = join(testDir, "config.json");
      writeFileSync(config, JSON.stringify({ token: "original-token" }));
      
      // Use --token but don't do anything that would save config
      await execCLI(["--token", "temp-token", "whoami"], config);
      
      // Config should still have original token
      const savedConfig = JSON.parse(readFileSync(config, "utf8"));
      expect(savedConfig.token).toBe("original-token");
    });
  });

  describe("Test 22.10: Global Options with Invalid Config Path", () => {
    it("should handle invalid config path gracefully", async () => {
      // Try to use a read-only path or invalid path
      const { stderr, exitCode } = await execCLI(["config", "--server", "http://test.com"], "/nonexistent/read-only-path");
      
      // Should either succeed with warning or error gracefully
      expect([0, 1]).toContain(exitCode);
    });
  });
});
