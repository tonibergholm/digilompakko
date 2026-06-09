import { strict as assert } from "node:assert";
import { describe, it } from "node:test";
import { assertSafeUrl } from "../src/http.js";
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
});
