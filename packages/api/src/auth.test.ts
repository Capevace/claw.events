import { describe, it, expect, beforeAll, afterAll, beforeEach } from "bun:test";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { spawn } from "node:child_process";
import {
  createTestContext,
  startClawkeyMockServer,
  startTestServer,
  cleanupTestContext,
  clearTestData,
  type TestContext,
} from "./test-utils.ts";

const createKeyPair = async () => {
  const tempDir = await mkdtemp(join(tmpdir(), "claw-events-auth-"));
  const keyPath = join(tempDir, "id_ed25519");

  await new Promise<void>((resolve, reject) => {
    const child = spawn("ssh-keygen", [
      "-t",
      "ed25519",
      "-N",
      "",
      "-C",
      "claw-events-test",
      "-f",
      keyPath
    ]);
    child.on("close", (code) => {
      if (code === 0) resolve();
      else reject(new Error("ssh-keygen failed"));
    });
    child.on("error", reject);
  });

  const publicKey = await readFile(`${keyPath}.pub`, "utf8");

  return {
    tempDir,
    keyPath,
    publicKey: publicKey.trim()
  };
};

const signMessage = async (message: string, keyPath: string) => {
  const tempDir = await mkdtemp(join(tmpdir(), "claw-events-sign-"));
  const messagePath = join(tempDir, "message.txt");
  const signaturePath = `${messagePath}.sig`;

  try {
    await writeFile(messagePath, message, "utf8");

    await new Promise<void>((resolve, reject) => {
      const child = spawn("ssh-keygen", [
        "-Y",
        "sign",
        "-n",
        "claw.events",
        "-f",
        keyPath,
        messagePath
      ]);
      child.on("close", (code) => {
        if (code === 0) resolve();
        else reject(new Error("ssh-keygen sign failed"));
      });
      child.on("error", reject);
    });

    const signature = await readFile(signaturePath, "utf8");
    return signature.trim();
  } finally {
    await rm(tempDir, { recursive: true, force: true });
  }
};

describe("Agent Authentication (Clawkey + SSH signature)", () => {
  let ctx: TestContext;

  beforeAll(async () => {
    ctx = await createTestContext();
    await startClawkeyMockServer(ctx, 9000);
    await startTestServer(ctx);
  });

  afterAll(async () => {
    await cleanupTestContext(ctx);
  });

  beforeEach(async () => {
    if (ctx.redis) {
      await clearTestData(ctx.redis);
    }
    ctx.publicKeys.clear();
  });

  it("Test 1: agent auth happy path + failure cases", async () => {
    const keyPair = await createKeyPair();
    const altKeyPair = await createKeyPair();

    ctx.publicKeys.set("testagent", new Map([[
      "main",
      keyPair.publicKey
    ]]));

    const initResponse = await fetch(`${ctx.config.apiUrl}/auth/agent/init`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ username: "testagent", key_name: "main" })
    });

    expect(initResponse.status).toBe(200);
    const initBody = await initResponse.json() as {
      username: string;
      key_name: string;
      nonce: string;
      message: string;
      expires_at: number;
    };

    expect(initBody.username).toBe("testagent");
    expect(initBody.key_name).toBe("main");
    expect(initBody.nonce).toBeDefined();
    expect(initBody.message).toContain("claw.events login");

    const signature = await signMessage(initBody.message, keyPair.keyPath);

    const verifyResponse = await fetch(`${ctx.config.apiUrl}/auth/agent/verify`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        username: "testagent",
        key_name: "main",
        nonce: initBody.nonce,
        signature
      })
    });

    expect(verifyResponse.status).toBe(200);
    const verifyBody = await verifyResponse.json() as { token?: string };
    expect(verifyBody.token).toBeDefined();

    const lockResponse = await fetch(`${ctx.config.apiUrl}/api/lock`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "Authorization": `Bearer ${verifyBody.token}`,
      },
      body: JSON.stringify({ channel: "agent.testagent.private" })
    });
    expect(lockResponse.status).toBe(200);

    // Invalid init payloads
    const initMissingUser = await fetch(`${ctx.config.apiUrl}/auth/agent/init`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({})
    });
    expect(initMissingUser.status).toBe(400);

    const initUnknownKey = await fetch(`${ctx.config.apiUrl}/auth/agent/init`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ username: "testagent", key_name: "unknown" })
    });
    expect(initUnknownKey.status).toBe(404);

    // Invalid verify payloads
    const verifyMissing = await fetch(`${ctx.config.apiUrl}/auth/agent/verify`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ username: "testagent" })
    });
    expect(verifyMissing.status).toBe(400);

    const verifyBadNonce = await fetch(`${ctx.config.apiUrl}/auth/agent/verify`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        username: "testagent",
        key_name: "main",
        nonce: "bad-nonce",
        signature
      })
    });
    expect(verifyBadNonce.status).toBe(400);

    // Replay should fail (nonce consumed)
    const verifyReplay = await fetch(`${ctx.config.apiUrl}/auth/agent/verify`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        username: "testagent",
        key_name: "main",
        nonce: initBody.nonce,
        signature
      })
    });
    expect(verifyReplay.status).toBe(400);

    // Invalid signature
    const initResponse2 = await fetch(`${ctx.config.apiUrl}/auth/agent/init`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ username: "testagent", key_name: "main" })
    });
    const initBody2 = await initResponse2.json() as { nonce: string; message: string };
    const badSignature = await signMessage(initBody2.message, altKeyPair.keyPath);

    const verifyBadSig = await fetch(`${ctx.config.apiUrl}/auth/agent/verify`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        username: "testagent",
        key_name: "main",
        nonce: initBody2.nonce,
        signature: badSignature
      })
    });
    expect(verifyBadSig.status).toBe(401);

    // Expired nonce
    const initResponse3 = await fetch(`${ctx.config.apiUrl}/auth/agent/init`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ username: "testagent", key_name: "main" })
    });
    const initBody3 = await initResponse3.json() as { nonce: string; message: string };

    const key = `agent_challenge:testagent:main:${initBody3.nonce}`;
    await ctx.redis!.expire(key, 1);
    await new Promise((resolve) => setTimeout(resolve, 1100));

    const signature3 = await signMessage(initBody3.message, keyPair.keyPath);
    const verifyExpired = await fetch(`${ctx.config.apiUrl}/auth/agent/verify`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        username: "testagent",
        key_name: "main",
        nonce: initBody3.nonce,
        signature: signature3
      })
    });
    expect(verifyExpired.status).toBe(400);

    await rm(keyPair.tempDir, { recursive: true, force: true });
    await rm(altKeyPair.tempDir, { recursive: true, force: true });
  });
});
