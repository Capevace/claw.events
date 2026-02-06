import { describe, it, expect, beforeAll, afterAll, beforeEach } from "bun:test";
import { existsSync, mkdirSync, writeFileSync, readFileSync, rmSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";

const TEST_API_URL = "http://localhost:3001";

const execCLI = async (args: string[], configPath?: string, envVars?: Record<string, string | undefined>): Promise<{ stdout: string; stderr: string; exitCode: number }> => {
  const cmd = [
    "bun",
    "run",
    "/Users/mat/dev/claw.events/packages/cli/src/index.ts",
    ...(configPath ? ["--config", configPath] : []),
    ...args
  ];

  const env: Record<string, string | undefined> = { ...process.env };
  
  // Handle CLAW_API_URL
  if (envVars && "CLAW_API_URL" in envVars) {
    if (envVars.CLAW_API_URL === undefined) {
      delete env.CLAW_API_URL; // Remove from env to use config
    } else {
      env.CLAW_API_URL = envVars.CLAW_API_URL;
    }
  } else {
    // Default to test URL
    env.CLAW_API_URL = TEST_API_URL;
  }
  
  // Copy any other additional env vars
  if (envVars) {
    for (const [key, value] of Object.entries(envVars)) {
      if (key !== "CLAW_API_URL") {
        env[key] = value;
      }
    }
  }

  const proc = Bun.spawn({
    cmd,
    stdout: "pipe",
    stderr: "pipe",
    env
  });

  const stdoutPromise = new Response(proc.stdout).text();
  const stderrPromise = new Response(proc.stderr).text();
  const exitCode = await proc.exited;
  const [stdout, stderr] = await Promise.all([stdoutPromise, stderrPromise]);

  return { stdout, stderr, exitCode };
};

describe("CLI Output Format Tests", () => {
  const testDir = join(tmpdir(), "claw-cli-output-test-" + Date.now());

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

  describe("Default Text Output", () => {
    it("should show human-readable help by default", async () => {
      const { stdout, exitCode } = await execCLI([], testDir);
      expect(exitCode).toBe(0);
      
      // Should contain human-readable elements, not JSON
      expect(stdout).toContain("claw.events CLI");
      expect(stdout).toContain("USAGE:");
      expect(stdout).toContain("COMMANDS:");
      expect(stdout).toContain("┌");
      expect(stdout).toContain("└");
      expect(stdout).not.toContain('"status": "help"');
    });

    it("should show human-readable whoami output", async () => {
      writeFileSync(join(testDir, "config.json"), JSON.stringify({
        username: "testuser",
        token: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.test"
      }));

      const { stdout, exitCode } = await execCLI(["whoami"], testDir);
      expect(exitCode).toBe(0);
      
      // Should contain human-readable elements
      expect(stdout).toContain("✓");
      expect(stdout).not.toContain('"status": "success"');
    });

    it("should show human-readable config --show output", async () => {
      writeFileSync(join(testDir, "config.json"), JSON.stringify({
        serverUrl: "http://localhost:3001"
      }));

      const { stdout, exitCode } = await execCLI(["config", "--show"], testDir);
      expect(exitCode).toBe(0);
      
      // Should contain human-readable elements
      expect(stdout).toContain("✓");
      expect(stdout).not.toContain('"status": "success"');
    });

    it("should show human-readable error output", async () => {
      const { stderr, exitCode } = await execCLI(["login"], testDir);
      expect(exitCode).toBe(1);
      
      // Should contain human-readable elements
      expect(stderr).toContain("✗");
      expect(stderr).toContain("Error:");
      expect(stderr).not.toContain('"status": "error"');
    });
  });

  describe("JSON Output Mode (--json flag)", () => {
    it("should show JSON help with --json flag", async () => {
      const { stdout, exitCode } = await execCLI(["--json"], testDir);
      expect(exitCode).toBe(0);
      
      // Should contain JSON structure
      expect(stdout).toContain('"status": "help"');
      expect(stdout).toContain('"commands"');
      
      const output = JSON.parse(stdout);
      expect(output.status).toBe("help");
      expect(output.commands).toBeDefined();
      expect(Array.isArray(output.commands)).toBe(true);
    });

    it("should show JSON whoami output with --json flag", async () => {
      writeFileSync(join(testDir, "config.json"), JSON.stringify({
        username: "testuser",
        token: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.test"
      }));

      const { stdout, exitCode } = await execCLI(["--json", "whoami"], testDir);
      expect(exitCode).toBe(0);
      
      const output = JSON.parse(stdout);
      expect(output.status).toBe("success");
      expect(output.data.authenticated).toBe(true);
      expect(output.data.username).toBe("testuser");
    });

    it("should show JSON config --show output with --json flag", async () => {
      writeFileSync(join(testDir, "config.json"), JSON.stringify({
        serverUrl: "http://localhost:3001"
      }));

      const { stdout, exitCode } = await execCLI(["--json", "config", "--show"], testDir);
      expect(exitCode).toBe(0);
      
      const output = JSON.parse(stdout);
      expect(output.status).toBe("success");
      expect(output.data.serverUrl).toBe("http://localhost:3001");
    });

    it("should show JSON error output with --json flag", async () => {
      const { stderr, exitCode } = await execCLI(["--json", "login"], testDir);
      expect(exitCode).toBe(1);
      
      const output = JSON.parse(stderr);
      expect(output.status).toBe("error");
      expect(output.error).toBeDefined();
      expect(Array.isArray(output.fixes)).toBe(true);
    });

    it("should work with -j shorthand for --json", async () => {
      const { stdout, exitCode } = await execCLI(["-j"], testDir);
      expect(exitCode).toBe(0);
      
      expect(stdout).toContain('"status": "help"');
      const output = JSON.parse(stdout);
      expect(output.status).toBe("help");
    });
  });

  describe("--version flag", () => {
    it("should show version in human-readable format by default", async () => {
      const { stdout, exitCode } = await execCLI(["--version"], testDir);
      expect(exitCode).toBe(0);
      
      expect(stdout).toContain("claw.events version");
      expect(stdout).toContain("1.0.2");
      expect(stdout).not.toContain('"version"');
    });

    it("should show version in JSON format with --json flag", async () => {
      const { stdout, exitCode } = await execCLI(["--json", "--version"], testDir);
      expect(exitCode).toBe(0);
      
      const output = JSON.parse(stdout);
      expect(output.status).toBe("success");
      expect(output.version).toBe("1.0.2");
      expect(output.name).toBe("claw.events");
    });

    it("should show version with version command", async () => {
      const { stdout, exitCode } = await execCLI(["version"], testDir);
      expect(exitCode).toBe(0);
      
      expect(stdout).toContain("claw.events version");
      expect(stdout).toContain("1.0.2");
    });

    it("should show JSON version with version command and --json flag", async () => {
      const { stdout, exitCode } = await execCLI(["--json", "version"], testDir);
      expect(exitCode).toBe(0);
      
      const output = JSON.parse(stdout);
      expect(output.version).toBe("1.0.2");
    });

    it("should work with -v shorthand for --version", async () => {
      const { stdout, exitCode } = await execCLI(["-v"], testDir);
      expect(exitCode).toBe(0);
      
      expect(stdout).toContain("1.0.2");
    });
  });

  describe("--help flag", () => {
    it("should show help in human-readable format by default", async () => {
      const { stdout, exitCode } = await execCLI(["--help"], testDir);
      expect(exitCode).toBe(0);
      
      expect(stdout).toContain("claw.events CLI");
      expect(stdout).toContain("USAGE:");
      expect(stdout).not.toContain('"status": "help"');
    });

    it("should show help in JSON format with --json flag", async () => {
      const { stdout, exitCode } = await execCLI(["--json", "--help"], testDir);
      expect(exitCode).toBe(0);
      
      const output = JSON.parse(stdout);
      expect(output.status).toBe("help");
      expect(output.commands).toBeDefined();
    });

    it("should work with -h shorthand for --help", async () => {
      const { stdout, exitCode } = await execCLI(["-h"], testDir);
      expect(exitCode).toBe(0);
      
      expect(stdout).toContain("claw.events CLI");
      expect(stdout).toContain("USAGE:");
    });

    it("should show command-specific help with --help", async () => {
      const { stdout, exitCode } = await execCLI(["login", "--help"], testDir);
      expect(exitCode).toBe(0);
      
      expect(stdout).toContain("Help: login");
      expect(stdout).toContain("Usage:");
    });

    it("should show command-specific help in JSON with --json flag", async () => {
      const { stdout, exitCode } = await execCLI(["--json", "login", "--help"], testDir);
      expect(exitCode).toBe(0);
      
      const output = JSON.parse(stdout);
      expect(output.status).toBe("help");
      expect(output.command).toBe("login");
    });
  });

  describe("Global Options Combined", () => {
    it("should combine --json with --server", async () => {
      const { stdout, exitCode } = await execCLI(["--json", "--server", "http://custom.example.com", "config", "--show"], testDir);
      expect(exitCode).toBe(0);
      
      const output = JSON.parse(stdout);
      expect(output.data.serverUrl).toBe("http://custom.example.com");
    });

    it("should combine --json with --token", async () => {
      const { stdout, exitCode } = await execCLI(["--json", "--token", "test-token-123", "whoami"], testDir);
      expect(exitCode).toBe(0);
      
      const output = JSON.parse(stdout);
      expect(output.data.authenticated).toBe(true);
      expect(output.data.globalOptions.hasToken).toBe(true);
    });

    it("should combine --json with --config", async () => {
      const customDir = join(testDir, "customconfig");
      mkdirSync(customDir, { recursive: true });
      writeFileSync(join(customDir, "config.json"), JSON.stringify({ serverUrl: "http://custom-server.com" }));
      
      // Don't pass testDir as configPath - use --config in args only
      // Don't set CLAW_API_URL so the config file value is used
      const { stdout, exitCode } = await execCLI(["--json", "--config", customDir, "config", "--show"], undefined, { CLAW_API_URL: undefined });
      expect(exitCode).toBe(0);
      
      const output = JSON.parse(stdout);
      expect(output.data.serverUrl).toBe("http://custom-server.com");
    });
  });
});
