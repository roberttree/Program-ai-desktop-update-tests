import assert from "node:assert/strict";
import test from "node:test";
import { makeNativeBudgetGuard } from "./native-budget.mjs";

const URL = "https://program-ai-desktop-api.vercel.app/api/desktop/v1/chat/completions";
const request = (changes = {}) => ({ method: "POST", headers: { Authorization: "Bearer fixture-not-live", "x-program-ai-model-provider": "openrouter" },
  body: JSON.stringify({ model: "openai/gpt-4.1-mini", stream: true, max_tokens: 512, messages: [{ role: "user", content: "Synthetic coding fixture" }],
    tools: [{ type: "function", function: { name: "write" } }], tool_choice: "auto", ...changes }) });
const fixture = (fetcher) => makeNativeBudgetGuard(fetcher, { expiresAtMs: Date.now() + 60000 });

test("factory is synchronous, self-contained and creates no network side effects", () => {
  let calls = 0;
  const guard = fixture(() => { calls++; });
  assert.equal(calls, 0); assert.equal(guard.read().attempted, 0);
  assert.equal(typeof (0, eval)("(" + makeNativeBudgetGuard.toString() + ")"), "function");
});
test("admitted requests preserve original input/init/body/header object identity", async () => {
  const init = request(), url = new globalThis.URL(URL);
  let calls = 0;
  const guard = fixture((actualInput, actualInit) => {
    calls++; assert.equal(actualInput, url); assert.equal(actualInit, init); return Promise.resolve(new Response("fixture"));
  });
  await guard.fetch(url, init);
  assert.equal(calls, 1); assert.deepEqual(guard.read().categories, []);
  assert.equal(guard.read().requestMutations, false); assert.equal(guard.read().maximumOutputTokens, 512);
  assert.doesNotMatch(JSON.stringify(guard.read()), /fixture-not-live|Synthetic coding fixture|Authorization|write/);
});
test("fifth dispatch and ambiguous failed requests never restore budget slots", async () => {
  let calls = 0;
  const guard = fixture(() => { calls++; return Promise.reject(new Error("fixture")); });
  for (let index = 0; index < 4; index++) await assert.rejects(guard.fetch(URL, request()));
  assert.throws(() => guard.fetch(URL, request()), /native_budget_request_rejected/);
  assert.equal(calls, 4); assert.equal(guard.read().attempted, 4); assert.deepEqual(guard.read().categories, ["attempt_limit"]);
});
test("oversized, unbounded, foreign-model and non-tool modes refuse before dispatch", () => {
  const changes = [{ messages: Array.from({ length: 33 }, () => ({ role: "user", content: "fixture" })) },
    { max_tokens: undefined }, { max_tokens: 513 }, { max_completion_tokens: 513 }, { model: "other/model" }, { tools: [] },
    { messages: [{ role: "user", content: "a".repeat(65537) }] }, { n: 2 }, { modalities: ["audio"] },
    { messages: [{ role: "user", content: [{ type: "image_url", image_url: { url: "https://example.invalid/large-image" } }] }] },
    { messages: [{ role: "user", content: "fixture", extra_private_content: "not-counted" }] }];
  for (const change of changes) {
    let calls = 0; const guard = fixture(() => { calls++; });
    assert.throws(() => guard.fetch(URL, request(change)), /native_budget_request_rejected/); assert.equal(calls, 0);
  }
});
test("voice and unexpected dedicated inference paths refuse; real auth exchange and other origins pass unchanged", () => {
  let calls = 0; const guard = fixture(() => { calls++; });
  for (const path of ["/api/desktop/v1/audio/transcriptions", "/api/desktop/v1/images/generations", "/api/unknown/paid"]) {
    assert.throws(() => guard.fetch("https://program-ai-desktop-api.vercel.app" + path, request()), /native_budget_request_rejected/);
  }
  assert.equal(calls, 0);
  guard.fetch("https://program-ai-desktop-api.vercel.app/api/auth/desktop/exchange", { method: "POST", body: "private-fixture-ticket" });
  guard.fetch("https://fpqasgxpogtkrpsakzuh.supabase.co/auth/v1/token", { method: "POST", body: "private-fixture-auth" });
  assert.equal(calls, 2); assert.equal(guard.read().attempted, 0);
});
test("guard enforces byte buffers and both max-token field variants, without serialization changes", async () => {
  const init = request({ max_tokens: undefined, max_completion_tokens: 512 }); init.body = Buffer.from(init.body);
  let calls = 0;
  const guard = fixture((_, body) => { calls++; assert.equal(body, init); return Promise.resolve(new Response()); });
  await guard.fetch(URL, init); assert.equal(calls, 1);
  const different = request(); different.headers["x-program-ai-model-provider"] = "replicate";
  assert.throws(() => guard.fetch(URL, different)); assert.equal(calls, 1);
});
test("unbounded or expired guard windows cannot be installed", () => {
  // A one-millisecond over-limit fixture can become valid while the test is
  // scheduled. Keep a generous margin; the guard's actual limit is unchanged.
  for (const expiresAtMs of [Date.now() - 1, Date.now() + 5400000, NaN, "future"]) {
    assert.throws(() => makeNativeBudgetGuard(() => {}, { expiresAtMs }), /configuration_rejected/);
  }
});
