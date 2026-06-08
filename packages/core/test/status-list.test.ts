import { test } from "node:test";
import assert from "node:assert/strict";
import {
  generateP256KeyPair,
  StatusList,
  buildStatusListToken,
  readStatus,
  STATUS_VALID,
  STATUS_INVALID,
  StaticTrustResolver,
} from "../src/index.js";

const ISSUER = "https://issuer.example";
const URI = `${ISSUER}/statuslist`;

test("StatusList: set/get and compress/decompress roundtrip", () => {
  const list = new StatusList(64);
  assert.equal(list.get(10), STATUS_VALID);
  list.set(10, 1);
  list.set(63, 1);
  assert.equal(list.get(10), STATUS_INVALID);
  assert.equal(list.get(63), STATUS_INVALID);
  assert.equal(list.get(11), STATUS_VALID);

  const bytes = StatusList.decodeBytes(list.encode());
  assert.equal((bytes[10 >> 3] >> (10 & 7)) & 1, 1);
});

test("Status List Token: valid then revoked", async () => {
  const keys = await generateP256KeyPair();
  const list = new StatusList(128);
  const idx = 42;

  let token = await buildStatusListToken(keys.privateJwk, ISSUER, URI, list);
  assert.equal(await readStatus(token, idx, keys.publicJwk), STATUS_VALID);

  list.set(idx, 1); // revoke
  token = await buildStatusListToken(keys.privateJwk, ISSUER, URI, list);
  assert.equal(await readStatus(token, idx, keys.publicJwk), STATUS_INVALID);
});

test("Status List Token: wrong key is rejected", async () => {
  const keys = await generateP256KeyPair();
  const attacker = await generateP256KeyPair();
  const token = await buildStatusListToken(keys.privateJwk, ISSUER, URI, new StatusList(8));
  await assert.rejects(() => readStatus(token, 0, attacker.publicJwk), /status list token invalid/);
});

test("StaticTrustResolver: untrusted issuer rejected before any fetch", async () => {
  const resolver = new StaticTrustResolver(["https://trusted.example"]);
  await assert.rejects(
    () => resolver.resolveIssuerKey("https://evil.example"),
    /not on trusted list/,
  );
});
