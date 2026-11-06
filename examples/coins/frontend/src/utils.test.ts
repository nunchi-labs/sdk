import assert from "node:assert/strict";
import { nextReconnectDelay, wsBase } from "./utils.ts";

assert.equal(wsBase("http://localhost:8080"), "ws://localhost:8080");
assert.equal(wsBase("HTTP://localhost:8080/"), "ws://localhost:8080");
assert.equal(wsBase("https://rpc.example:443/path"), "wss://rpc.example/path");
assert.equal(wsBase("https://rpc.example/path?x=1#y"), "wss://rpc.example/path");
assert.equal(wsBase("ws://localhost:8080/live"), "ws://localhost:8080/live");
assert.equal(wsBase("localhost:8080"), "ws://localhost:8080");
{
  let rejected = false;
  try {
    wsBase("javascript:alert(1)");
  } catch (error) {
    rejected = true;
    assert.match(String(error), /valid http\(s\) or ws\(s\) URL/);
  }
  assert.equal(rejected, true);
}

assert.equal(nextReconnectDelay(0), 1000);
assert.equal(nextReconnectDelay(1000), 2000);
assert.equal(nextReconnectDelay(16000), 30000);
assert.equal(nextReconnectDelay(30000), 30000);
assert.equal(nextReconnectDelay(Number.NaN), 1000);

console.log("utils tests passed");
