"use strict";

const token = document.querySelector("meta[name='sigil-token']").content;
const nav = document.getElementById("tool-nav");
const tabs = document.getElementById("tool-tabs");
const form = document.getElementById("operation-form");
const title = document.getElementById("tool-title");
const subtitle = document.getElementById("tool-subtitle");
const output = document.getElementById("result-output");
const resultMeta = document.getElementById("result-meta");
const activityLog = document.getElementById("activity-log");
const analysisStrip = document.getElementById("analysis-strip");
const copyButton = document.getElementById("copy-result");
const saveButton = document.getElementById("save-result");

let activeTool = "digest";
let lastResult = "{}";

const tools = [
  { id: "digest", label: "Digest", subtitle: "SHA-2 and SHA-3 message fingerprints" },
  { id: "hmac", label: "HMAC", subtitle: "Keyed authentication tags" },
  { id: "entropy", label: "Entropy", subtitle: "Byte distribution and randomness inspection" },
  { id: "random", label: "Random", subtitle: "CSPRNG bytes and passphrases" },
  { id: "xor", label: "XOR", subtitle: "Fixed and repeating XOR transforms" },
  { id: "keys", label: "Keys", subtitle: "Ed25519 key material" },
  { id: "sign", label: "Sign", subtitle: "Ed25519 signatures" },
  { id: "verify", label: "Verify", subtitle: "Ed25519 signature checks" },
  { id: "seal", label: "Seal", subtitle: "AES-256-GCM authenticated file envelopes" }
];

function init() {
  renderNavigation();
  renderTool(activeTool);
  copyButton.addEventListener("click", copyResult);
  saveButton.addEventListener("click", saveResult);
  logActivity("Sigil session ready");
}

function renderNavigation() {
  nav.textContent = "";
  tabs.textContent = "";
  for (const tool of tools) {
    nav.appendChild(toolButton(tool, "tool-button"));
    tabs.appendChild(toolButton(tool, "tab-button"));
  }
}

function toolButton(tool, className) {
  const button = document.createElement("button");
  button.type = "button";
  button.className = className;
  button.dataset.tool = tool.id;
  button.textContent = tool.label;
  button.addEventListener("click", () => renderTool(tool.id));
  return button;
}

function renderTool(id) {
  activeTool = id;
  const tool = tools.find((item) => item.id === id);
  title.textContent = tool.label;
  subtitle.textContent = tool.subtitle;
  document.querySelectorAll("[data-tool]").forEach((button) => {
    button.classList.toggle("active", button.dataset.tool === id);
  });

  form.textContent = "";
  form.appendChild(toolFields(id));
  form.onsubmit = async (event) => {
    event.preventDefault();
    await runActiveTool();
  };
  attachFileLoaders();
}

function toolFields(id) {
  const fragment = document.createDocumentFragment();
  const grid = document.createElement("div");
  grid.className = "field-grid";

  if (id === "digest") {
    grid.append(dataField("Input", "data", "encoding"));
    grid.append(selectField("Algorithm", "algorithm", hashOptions(["sha256", "sha384", "sha512", "sha3-256", "sha3-384", "sha3-512", "sha1", "md5"]), "sha256"));
    grid.append(actionRow("Compute digest"));
  } else if (id === "hmac") {
    grid.append(dataField("Message", "data", "encoding"));
    grid.append(textField("Key material", "key", "textarea"));
    grid.append(selectField("Key encoding", "keyEncoding", ["hex", "base64", "text"], "hex"));
    grid.append(selectField("Algorithm", "algorithm", hashOptions(["sha256", "sha384", "sha512", "sha3-256", "sha3-384", "sha3-512"]), "sha256"));
    grid.append(actionRow("Compute HMAC"));
  } else if (id === "entropy") {
    grid.append(dataField("Sample", "data", "encoding"));
    grid.append(actionRow("Analyze entropy"));
  } else if (id === "random") {
    grid.append(selectField("Material", "kind", ["bytes", "password"], "bytes"));
    grid.append(numberField("Size", "size", 32, 1, 1048576));
    grid.append(selectField("Output", "output", ["hex", "base64"], "hex"));
    grid.append(actionRow("Generate"));
  } else if (id === "xor") {
    grid.append(textField("Left", "left", "textarea"));
    grid.append(textField("Right or key", "right", "textarea"));
    grid.append(selectField("Mode", "mode", ["fixed", "repeating"], "fixed"));
    grid.append(selectField("Input encoding", "encoding", ["hex", "base64", "text"], "hex"));
    grid.append(selectField("Output", "output", ["hex", "base64", "text"], "hex"));
    grid.append(actionRow("Run XOR"));
  } else if (id === "keys") {
    grid.append(actionRow("Generate Ed25519 pair"));
  } else if (id === "sign") {
    grid.append(textField("Private key PEM", "privatePem", "textarea"));
    grid.append(dataField("Message", "data", "encoding"));
    grid.append(actionRow("Sign message"));
  } else if (id === "verify") {
    grid.append(textField("Public key PEM", "publicPem", "textarea"));
    grid.append(textField("Signature base64", "signature", "textarea"));
    grid.append(dataField("Message", "data", "encoding"));
    grid.append(actionRow("Verify signature"));
  } else if (id === "seal") {
    grid.append(selectField("Operation", "sealAction", ["seal", "open"], "seal"));
    grid.append(secretField("Passphrase", "passphrase"));
    grid.append(numberField("PBKDF2 iterations", "iterations", 600000, 100000, 5000000));
    grid.append(selectField("Open output", "output", ["base64", "text", "hex"], "base64"));
    grid.append(dataField("Plaintext or sealed base64", "data", "encoding"));
    grid.append(actionRow("Run seal operation"));
  }

  fragment.appendChild(grid);
  return fragment;
}

function hashOptions(values) {
  return values;
}

function dataField(labelText, dataId, encodingId) {
  const wrap = document.createElement("div");
  wrap.className = "wide-field";

  const label = document.createElement("label");
  label.htmlFor = dataId;
  label.textContent = labelText;
  wrap.appendChild(label);

  const drop = document.createElement("div");
  drop.className = "drop-row";

  const fileStatus = document.createElement("span");
  fileStatus.className = "file-status";
  fileStatus.textContent = "No file loaded";

  const fileLabel = document.createElement("label");
  fileLabel.className = "file-button";
  fileLabel.textContent = "Load file";
  const file = document.createElement("input");
  file.className = "hidden-file";
  file.type = "file";
  file.dataset.target = dataId;
  file.dataset.encoding = encodingId;
  fileLabel.appendChild(file);

  drop.append(fileStatus, fileLabel);
  wrap.appendChild(drop);

  const textarea = document.createElement("textarea");
  textarea.id = dataId;
  textarea.name = dataId;
  textarea.spellcheck = false;
  textarea.autocomplete = "off";
  textarea.placeholder = "";
  wrap.appendChild(textarea);

  const encoding = selectField("Input encoding", encodingId, ["text", "hex", "base64"], "text");
  wrap.appendChild(encoding);
  return wrap;
}

function textField(labelText, id, kind) {
  const wrap = document.createElement("div");
  wrap.className = "wide-field";
  const label = document.createElement("label");
  label.htmlFor = id;
  label.textContent = labelText;
  const input = kind === "textarea" ? document.createElement("textarea") : document.createElement("input");
  input.id = id;
  input.name = id;
  input.spellcheck = false;
  input.autocomplete = "off";
  wrap.append(label, input);
  return wrap;
}

function secretField(labelText, id) {
  const wrap = document.createElement("div");
  wrap.className = "field";
  const label = document.createElement("label");
  label.htmlFor = id;
  label.textContent = labelText;
  const input = document.createElement("input");
  input.type = "password";
  input.id = id;
  input.name = id;
  input.autocomplete = "off";
  wrap.append(label, input);
  return wrap;
}

function selectField(labelText, id, options, selected) {
  const wrap = document.createElement("div");
  wrap.className = "field";
  const label = document.createElement("label");
  label.htmlFor = id;
  label.textContent = labelText;
  const select = document.createElement("select");
  select.id = id;
  select.name = id;
  for (const value of options) {
    const option = document.createElement("option");
    option.value = value;
    option.textContent = value;
    option.selected = value === selected;
    select.appendChild(option);
  }
  wrap.append(label, select);
  return wrap;
}

function numberField(labelText, id, value, min, max) {
  const wrap = document.createElement("div");
  wrap.className = "field";
  const label = document.createElement("label");
  label.htmlFor = id;
  label.textContent = labelText;
  const input = document.createElement("input");
  input.type = "number";
  input.id = id;
  input.name = id;
  input.min = String(min);
  input.max = String(max);
  input.value = String(value);
  wrap.append(label, input);
  return wrap;
}

function actionRow(label) {
  const row = document.createElement("div");
  row.className = "wide-field action-row";
  const button = document.createElement("button");
  button.className = "primary-button";
  button.type = "submit";
  button.textContent = label;
  row.appendChild(button);
  return row;
}

function attachFileLoaders() {
  form.querySelectorAll("input[type='file']").forEach((input) => {
    input.addEventListener("change", async () => {
      const file = input.files[0];
      if (!file) return;
      const bytes = new Uint8Array(await file.arrayBuffer());
      const target = document.getElementById(input.dataset.target);
      const encoding = document.getElementById(input.dataset.encoding);
      target.value = bytesToBase64(bytes);
      encoding.value = "base64";
      const status = input.closest(".drop-row").querySelector(".file-status");
      status.textContent = `${file.name} | ${bytes.length} bytes`;
    });
  });
}

async function runActiveTool() {
  const payload = collectPayload();
  const endpoint = activeTool === "seal" && payload.sealAction === "open" ? "/api/open" : `/api/${activeTool}`;
  if (payload.sealAction) delete payload.sealAction;
  setBusy(true);
  try {
    const result = await postJSON(endpoint, payload);
    showResult(result, activeTool);
    logActivity(`${tools.find((item) => item.id === activeTool).label} complete`);
  } catch (error) {
    showError(error);
  } finally {
    setBusy(false);
  }
}

function collectPayload() {
  const value = (id) => form.querySelector(`#${id}`)?.value ?? "";
  if (activeTool === "digest") {
    return { data: value("data"), encoding: value("encoding"), algorithm: value("algorithm") };
  }
  if (activeTool === "hmac") {
    return { data: value("data"), encoding: value("encoding"), key: value("key"), keyEncoding: value("keyEncoding"), algorithm: value("algorithm") };
  }
  if (activeTool === "entropy") {
    return { data: value("data"), encoding: value("encoding") };
  }
  if (activeTool === "random") {
    return { kind: value("kind"), size: Number(value("size")), output: value("output") };
  }
  if (activeTool === "xor") {
    return { left: value("left"), right: value("right"), mode: value("mode"), encoding: value("encoding"), output: value("output") };
  }
  if (activeTool === "keys") {
    return {};
  }
  if (activeTool === "sign") {
    return { privatePem: value("privatePem"), data: value("data"), encoding: value("encoding") };
  }
  if (activeTool === "verify") {
    return { publicPem: value("publicPem"), signature: value("signature"), data: value("data"), encoding: value("encoding") };
  }
  if (activeTool === "seal") {
    const action = value("sealAction");
    if (action === "open") {
      return { sealAction: action, sealedBase64: value("data"), passphrase: value("passphrase"), output: value("output") };
    }
    return { sealAction: action, data: value("data"), encoding: value("encoding"), passphrase: value("passphrase"), iterations: Number(value("iterations")) };
  }
  return {};
}

async function postJSON(endpoint, payload) {
  const response = await fetch(endpoint, {
    method: "POST",
    credentials: "same-origin",
    headers: {
      "Content-Type": "application/json",
      "X-Sigil-Token": token
    },
    body: JSON.stringify(payload)
  });
  const data = await response.json();
  if (!response.ok) {
    throw new Error(data.error || "Operation failed");
  }
  return data;
}

function showResult(data, toolId) {
  lastResult = JSON.stringify(data, null, 2);
  output.textContent = lastResult;
  resultMeta.textContent = resultSummary(data, toolId);
  renderChips(data, toolId);
}

function showError(error) {
  const data = { error: error.message };
  lastResult = JSON.stringify(data, null, 2);
  output.textContent = lastResult;
  resultMeta.textContent = "Operation rejected";
  analysisStrip.textContent = "";
  const chip = document.createElement("span");
  chip.className = "chip bad";
  chip.textContent = "Rejected";
  analysisStrip.appendChild(chip);
  logActivity("Operation rejected");
}

function resultSummary(data, toolId) {
  if (data.error) return "Rejected";
  if (toolId === "digest" || toolId === "hmac") return `${data.algorithm.name} | ${data.size} bytes`;
  if (toolId === "entropy") return `${data.size} bytes | ${data.shannonBitsPerByte} bits per byte`;
  if (toolId === "random") return data.kind === "password" ? `${data.length} characters` : `${data.size} bytes`;
  if (toolId === "xor") return `${data.size} bytes | ${data.encoding}`;
  if (toolId === "keys") return "Ed25519 key pair";
  if (toolId === "sign") return `${data.algorithm} | ${data.size} bytes`;
  if (toolId === "verify") return data.valid ? "Signature valid" : "Signature invalid";
  if (toolId === "seal") return data.sealedSize ? `${data.inputSize} bytes sealed` : `${data.plainSize} bytes opened`;
  return "Complete";
}

function renderChips(data, toolId) {
  analysisStrip.textContent = "";
  const chips = [];
  if (toolId === "digest" || toolId === "hmac") {
    chips.push(["strong", data.algorithm.family]);
    chips.push([data.algorithm.deprecated ? "bad" : "strong", data.algorithm.deprecated ? "Deprecated" : `${data.algorithm.bits} bit`]);
  } else if (toolId === "entropy") {
    chips.push(["strong", `${data.uniqueBytes} unique bytes`]);
    chips.push([data.shannonBitsPerByte >= 7.75 ? "strong" : "warn", `${data.shannonBitsPerByte} bits per byte`]);
    chips.push(["", data.assessment]);
  } else if (toolId === "random") {
    chips.push(["strong", "CSPRNG"]);
    chips.push(["", data.encoding || "password"]);
  } else if (toolId === "verify") {
    chips.push([data.valid ? "strong" : "bad", data.valid ? "Valid" : "Invalid"]);
  } else if (toolId === "seal" && data.info) {
    chips.push(["strong", data.info.algorithm]);
    chips.push(["", data.info.kdf]);
    chips.push(["", `${data.info.iterations} iterations`]);
  } else if (toolId === "keys" || toolId === "sign") {
    chips.push(["strong", "Ed25519"]);
  }
  for (const [kind, label] of chips) {
    const chip = document.createElement("span");
    chip.className = `chip ${kind}`.trim();
    chip.textContent = label;
    analysisStrip.appendChild(chip);
  }
}

function logActivity(message) {
  const item = document.createElement("li");
  const stamp = new Date().toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" });
  item.textContent = `${stamp} ${message}`;
  activityLog.prepend(item);
  while (activityLog.children.length > 7) {
    activityLog.removeChild(activityLog.lastChild);
  }
}

function setBusy(isBusy) {
  const button = form.querySelector(".primary-button");
  if (!button) return;
  button.disabled = isBusy;
  if (isBusy) {
    button.dataset.label = button.textContent;
    button.textContent = "Working";
  } else {
    button.textContent = button.dataset.label || "Run";
  }
}

async function copyResult() {
  try {
    await navigator.clipboard.writeText(lastResult);
    logActivity("Result copied");
  } catch {
    logActivity("Copy unavailable");
  }
}

function saveResult() {
  const blob = new Blob([lastResult, "\n"], { type: "application/json" });
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement("a");
  anchor.href = url;
  anchor.download = "sigil-result.json";
  document.body.appendChild(anchor);
  anchor.click();
  anchor.remove();
  URL.revokeObjectURL(url);
  logActivity("Result saved");
}

function bytesToBase64(bytes) {
  let binary = "";
  const chunk = 0x8000;
  for (let i = 0; i < bytes.length; i += chunk) {
    binary += String.fromCharCode(...bytes.subarray(i, i + chunk));
  }
  return btoa(binary);
}

init();
