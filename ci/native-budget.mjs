// Portable reject-only diagnostic guard. Factory is synchronous so a guarded
// native inspector can install it before resuming app code. No import effects.
export function makeNativeBudgetGuard(originalFetch, options) {
  const origin = "https://program-ai-desktop-api.vercel.app";
  const chat = "/api/desktop/v1/chat/completions";
  if (typeof originalFetch !== "function" || !options || !Number.isSafeInteger(options.expiresAtMs) ||
    options.expiresAtMs <= Date.now() || options.expiresAtMs - Date.now() > 2700000) throw new Error("native_budget_configuration_rejected");
  let attempted = 0, rejected = 0, maximumBodyBytes = 0, maximumMessages = 0, maximumOutputTokens = 0;
  const categories = new Set();
  const refuse = (category) => {
    rejected = Math.min(16, rejected + 1); categories.add(category);
    throw new Error("native_budget_request_rejected");
  };
  const guarded = function(input, init) {
    let url;
    try { url = new URL(typeof input === "string" || input instanceof URL ? input : input.url); }
    catch { return originalFetch(input, init); }
    if (url.origin !== origin) return originalFetch(input, init);
    const method = String(init?.method ?? (typeof input === "object" && input?.method) ?? "GET").toUpperCase();
    if (method !== "POST") {
      if (url.pathname === chat || url.pathname.includes("/audio/") || url.pathname.includes("/transcriptions")) return refuse("unexpected_inference");
      return originalFetch(input, init);
    }
    if (url.pathname === "/api/auth/desktop/exchange" && !url.search && !url.hash && !url.username && !url.password) return originalFetch(input, init);
    if (url.pathname !== chat) return refuse("unexpected_inference");
    if (Date.now() >= options.expiresAtMs) return refuse("expired");
    if (url.search || url.hash || url.username || url.password) return refuse("destination");
    let bytes;
    if (typeof init?.body === "string") bytes = new TextEncoder().encode(init.body);
    else if (ArrayBuffer.isView(init?.body)) bytes = new Uint8Array(init.body.buffer, init.body.byteOffset, init.body.byteLength);
    else if (init?.body instanceof ArrayBuffer) bytes = new Uint8Array(init.body);
    else return refuse("body_contract");
    if (bytes.byteLength > 65536) return refuse("body_limit");
    let body;
    try { body = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bytes)); }
    catch { return refuse("body_contract"); }
    const allowedKeys = ["model", "messages", "stream", "stream_options", "usage", "max_tokens", "max_completion_tokens",
      "temperature", "top_p", "stop", "tools", "tool_choice", "parallel_tool_calls", "n"];
    if (!body || typeof body !== "object" || Array.isArray(body) || Object.keys(body).some((key) => !allowedKeys.includes(key)) || body.model !== "openai/gpt-4.1-mini" ||
      body.stream !== true || body.n !== undefined && body.n !== 1 || !Array.isArray(body.messages) ||
      body.messages.length < 1 || body.messages.length > 32 || !Array.isArray(body.tools) || !body.tools.length ||
      body.tool_choice !== undefined && body.tool_choice !== "auto") return refuse("mode_contract");
    if (!body.messages.every((message) => message && typeof message === "object" && !Array.isArray(message) &&
      ["system", "user", "assistant", "tool"].includes(message.role) &&
      (typeof message.content === "string" || message.content === null || message.content === undefined) &&
      Object.keys(message).every((key) => ["role", "content", "name", "tool_calls", "tool_call_id"].includes(key)) &&
      (message.tool_calls === undefined || Array.isArray(message.tool_calls) && message.tool_calls.every((tool) => tool &&
        typeof tool === "object" && tool.type === "function" && typeof tool.id === "string" &&
        tool.function && typeof tool.function.name === "string" && typeof tool.function.arguments === "string" &&
        Object.keys(tool).every((key) => ["id", "type", "function"].includes(key)) &&
        Object.keys(tool.function).every((key) => ["name", "arguments"].includes(key)))))) return refuse("text_contract");
    const outputs = [body.max_tokens, body.max_completion_tokens].filter((value) => value !== undefined);
    if (!outputs.length || !outputs.every((value) => Number.isSafeInteger(value) && value >= 1 && value <= 512)) return refuse("output_limit");
    const headers = new Headers(init?.headers ?? (typeof input === "object" ? input?.headers : undefined));
    if (headers.has("x-program-ai-model-provider") && headers.get("x-program-ai-model-provider") !== "openrouter") return refuse("provider_contract");
    if (attempted >= 4) return refuse("attempt_limit");
    attempted++; // An ambiguous/error response NEVER restores this attempt.
    maximumBodyBytes = Math.max(maximumBodyBytes, bytes.byteLength);
    maximumMessages = Math.max(maximumMessages, body.messages.length);
    maximumOutputTokens = Math.max(maximumOutputTokens, ...outputs);
    return originalFetch(input, init); // Same original input/init/body/headers.
  };
  return Object.freeze({ fetch: guarded, read() { return {
    attempted, rejected, categories: [...categories].sort(), maximumBodyBytes, maximumMessages, maximumOutputTokens,
    expired: Date.now() >= options.expiresAtMs, requestMutations: false, inferenceMocked: false,
  }; } });
}
