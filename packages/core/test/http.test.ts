import { strict as assert } from "node:assert";
import { describe, it } from "node:test";
import * as http from "node:http";
import { assertSafeUrl, safeFetch, safeFetchText } from "../src/http.js";
import { Oid4vcError } from "../src/errors.js";

describe("assertSafeUrl", () => {
  it("accepts HTTPS URLs", () => {
    const url = assertSafeUrl("https://example.com/jwks.json");
    assert.equal(url.hostname, "example.com");
  });

  it("accepts HTTP to localhost", () => {
    const url = assertSafeUrl("http://localhost:4001/.well-known/openid-credential-issuer");
    assert.equal(url.hostname, "localhost");
  });

  it("accepts HTTP to 127.0.0.1", () => {
    const url = assertSafeUrl("http://127.0.0.1:4002/jwks.json");
    assert.equal(url.hostname, "127.0.0.1");
  });

  it("accepts HTTP to [::1]", () => {
    const url = assertSafeUrl("http://[::1]:4000/jwks.json");
    assert.equal(url.hostname, "[::1]");
  });

  it("rejects HTTP to a non-loopback host", () => {
    assert.throws(
      () => assertSafeUrl("http://evil.internal/steal-tokens"),
      (e: unknown) => e instanceof Oid4vcError && (e as Oid4vcError).code === "invalid_request",
    );
  });

  it("rejects HTTP to a public IP", () => {
    assert.throws(
      () => assertSafeUrl("http://169.254.169.254/latest/meta-data/"),
      (e: unknown) => e instanceof Oid4vcError,
    );
  });

  it("rejects a completely invalid URL", () => {
    assert.throws(
      () => assertSafeUrl("not-a-url"),
      (e: unknown) => e instanceof Oid4vcError && (e as Oid4vcError).code === "invalid_request",
    );
  });

  it("rejects a file:// URL", () => {
    assert.throws(
      () => assertSafeUrl("file:///etc/passwd"),
      (e: unknown) => e instanceof Oid4vcError,
    );
  });

  it("rejects an ftp:// URL", () => {
    assert.throws(
      () => assertSafeUrl("ftp://example.com/data"),
      (e: unknown) => e instanceof Oid4vcError,
    );
  });

  // Private / link-local IP blocking (SSRF hardening)
  it("blocks RFC 1918 10.x range over HTTPS", () => {
    assert.throws(() => assertSafeUrl("https://10.0.0.1/secret"), /private/i);
  });
  it("blocks RFC 1918 172.16.x range over HTTPS", () => {
    assert.throws(() => assertSafeUrl("https://172.16.255.255/"), /private/i);
  });
  it("blocks RFC 1918 192.168.x range over HTTPS", () => {
    assert.throws(() => assertSafeUrl("https://192.168.1.1/"), /private/i);
  });
  it("blocks link-local / metadata endpoint over HTTPS", () => {
    assert.throws(() => assertSafeUrl("https://169.254.169.254/"), /private/i);
  });
  it("blocks ULA IPv6 over HTTPS", () => {
    assert.throws(() => assertSafeUrl("https://[fc00::1]/"), /private/i);
  });
  it("blocks link-local IPv6 over HTTPS", () => {
    assert.throws(() => assertSafeUrl("https://[fe80::1]/"), /private/i);
  });
  it("still allows localhost", () => {
    assert.doesNotThrow(() => assertSafeUrl("http://localhost:4001/"));
  });
  it("still allows 127.0.0.1", () => {
    assert.doesNotThrow(() => assertSafeUrl("http://127.0.0.1:4001/"));
  });

  // IPv4-mapped IPv6 SSRF bypass (WHATWG normalises to hex form)
  it("blocks IPv4-mapped IPv6 ::ffff:10.0.0.1 (dotted-decimal form)", () => {
    // Node's URL parser normalises ::ffff:10.0.0.1 → ::ffff:a00:1
    assert.throws(() => assertSafeUrl("https://[::ffff:10.0.0.1]/"), /private/i);
  });
  it("blocks IPv4-mapped IPv6 ::ffff:169.254.169.254 (hex form after WHATWG normalisation)", () => {
    // WHATWG normalises 169.254.169.254 → a9fe:a9fe
    assert.throws(() => assertSafeUrl("https://[::ffff:169.254.169.254]/"), /private/i);
  });
  it("blocks IPv4-mapped IPv6 hex form ::ffff:a00:1 directly", () => {
    assert.throws(() => assertSafeUrl("https://[::ffff:a00:1]/"), /private/i);
  });
  it("blocks IPv4-mapped IPv6 hex form ::ffff:a9fe:a9fe directly", () => {
    assert.throws(() => assertSafeUrl("https://[::ffff:a9fe:a9fe]/"), /private/i);
  });
});

describe("safeFetch redirect safety", () => {
  it("safeFetch: redirect to private IP is rejected", async () => {
    const server = http.createServer((_req, res) => {
      res.writeHead(302, { Location: "https://10.0.0.1/steal" });
      res.end();
    });
    await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
    const { port } = server.address() as { port: number };
    await assert.rejects(
      () => safeFetch(`http://127.0.0.1:${port}/redirect`),
      /private/i,
    );
    server.close();
  });

  it("safeFetch: Authorization header is NOT forwarded on cross-origin redirect", async () => {
    // Server B: echo back the Authorization header (or its absence) in the response body.
    let receivedAuthOnB: string | null = "not-yet-set";
    const serverB = http.createServer((req, res) => {
      receivedAuthOnB = req.headers["authorization"] ?? null;
      res.writeHead(200, { "Content-Type": "text/plain" });
      res.end("ok");
    });
    await new Promise<void>((resolve) => serverB.listen(0, "127.0.0.1", resolve));
    const portB = (serverB.address() as { port: number }).port;

    // Server A: redirect to server B (different port = different origin).
    const serverA = http.createServer((_req, res) => {
      res.writeHead(302, { Location: `http://127.0.0.1:${portB}/dest` });
      res.end();
    });
    await new Promise<void>((resolve) => serverA.listen(0, "127.0.0.1", resolve));
    const portA = (serverA.address() as { port: number }).port;

    try {
      await safeFetch(`http://127.0.0.1:${portA}/start`, {
        headers: { Authorization: "Bearer secret-token" },
      });
      // Authorization must not have reached server B.
      assert.equal(
        receivedAuthOnB,
        null,
        "Authorization header must be stripped on cross-origin redirect",
      );
    } finally {
      serverA.close();
      serverB.close();
    }
  });
});

describe("safeFetchText body size cap", () => {
  it("safeFetchText: aborts body larger than MAX_BODY_BYTES", async () => {
    const big = Buffer.alloc(2 * 1024 * 1024, 0x41); // 2 MiB of 'A'
    const server = http.createServer((_req, res) => {
      res.writeHead(200, { "Content-Type": "text/plain" });
      res.end(big);
    });
    await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
    const { port } = server.address() as { port: number };
    await assert.rejects(
      () => safeFetchText(`http://127.0.0.1:${port}/big`),
      /too large/i,
    );
    server.close();
  });
});
