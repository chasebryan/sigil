"use strict";

const token = document.querySelector("meta[name='sigil-token']").content;
const nav = document.getElementById("tool-nav");
const form = document.getElementById("operation-form");
const title = document.getElementById("tool-title");
const subtitle = document.getElementById("tool-subtitle");
const output = document.getElementById("result-output");
const resultMeta = document.getElementById("result-meta");
const resultSummaryPanel = document.getElementById("result-summary");
const activityLog = document.getElementById("activity-log");
const analysisStrip = document.getElementById("analysis-strip");
const copyArtifactButton = document.getElementById("copy-artifact");
const copyButton = document.getElementById("copy-result");
const saveButton = document.getElementById("save-result");
const clearResultButton = document.getElementById("clear-result");

const maxClientPayloadBytes = 24 * 1024 * 1024;
const textEncoder = new TextEncoder();

let activeTool = "digest";
let lastResult = `{
  "status": "ready",
  "scope": "local"
}`;
let lastPrimaryArtifact = null;

const tools = [
  { id: "digest", label: "Digest", subtitle: "SHA-2 and SHA-3 message fingerprints", group: "Analysis", icon: "hash" },
  { id: "hmac", label: "HMAC", subtitle: "Keyed authentication tags", group: "Analysis", icon: "mac" },
  { id: "entropy", label: "Entropy", subtitle: "Byte distribution and randomness inspection", group: "Analysis", icon: "entropy" },
  { id: "xor", label: "XOR", subtitle: "Fixed and repeating XOR transforms", group: "Analysis", icon: "xor" },
  { id: "profile", label: "Profile", subtitle: "Cryptanalytic structure and periodicity triage", group: "Research", icon: "profile" },
  { id: "random", label: "Random", subtitle: "CSPRNG bytes and passphrases", group: "Material", icon: "random" },
  { id: "keys", label: "Keys", subtitle: "Ed25519 key material", group: "Material", icon: "key" },
  { id: "sign", label: "Sign", subtitle: "Ed25519 signatures", group: "Signatures", icon: "sign" },
  { id: "verify", label: "Verify", subtitle: "Ed25519 signature checks", group: "Signatures", icon: "verify" },
  { id: "seal", label: "Seal", subtitle: "AES-256-GCM authenticated file envelopes", group: "Envelope", icon: "seal" }
];

function init() {
  renderNavigation();
  renderTool(activeTool);
  renderReadyResult();
  copyArtifactButton?.addEventListener("click", copyPrimaryArtifact);
  copyButton?.addEventListener("click", copyResult);
  saveButton?.addEventListener("click", saveResult);
  clearResultButton?.addEventListener("click", clearResult);
  logActivity("Sigil session ready");
}

function renderNavigation() {
  nav.textContent = "";
  let currentGroup = "";
  for (const tool of tools) {
    if (tool.group !== currentGroup) {
      currentGroup = tool.group;
      const group = document.createElement("div");
      group.className = "nav-group-label";
      group.textContent = currentGroup;
      nav.appendChild(group);
    }
    nav.appendChild(toolButton(tool, "tool-button"));
  }
}

function toolButton(tool, className) {
  const button = document.createElement("button");
  button.type = "button";
  button.className = className;
  button.dataset.tool = tool.id;
  button.appendChild(toolIcon(tool.icon));
  const label = document.createElement("span");
  label.className = "tool-label";
  label.textContent = tool.label;
  button.appendChild(label);
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
}

function toolFields(id) {
  const fragment = document.createDocumentFragment();
  const stack = document.createElement("div");
  stack.className = "form-stack";

  if (id === "digest") {
    stack.append(sectionBlock("Input", [dataField("Message or file", "data", "encoding")]));
    stack.append(sectionBlock("Parameters", [selectField("Algorithm", "algorithm", hashOptions(["sha256", "sha384", "sha512", "sha3-256", "sha3-384", "sha3-512", "sha1", "md5"]), "sha256")]));
    stack.append(actionRow("Compute digest"));
  } else if (id === "hmac") {
    stack.append(sectionBlock("Message", [dataField("Message or file", "data", "encoding")]));
    stack.append(sectionBlock("Key", [textField("Key material", "key", "textarea")]));
    stack.append(sectionBlock("Parameters", [
      selectField("Key encoding", "keyEncoding", ["hex", "base64", "text"], "hex"),
      selectField("Algorithm", "algorithm", hashOptions(["sha256", "sha384", "sha512", "sha3-256", "sha3-384", "sha3-512"]), "sha256")
    ]));
    stack.append(actionRow("Compute HMAC"));
  } else if (id === "entropy") {
    stack.append(sectionBlock("Sample", [dataField("Bytes or file", "data", "encoding")]));
    stack.append(actionRow("Analyze entropy"));
  } else if (id === "profile") {
    stack.append(sectionBlock("Sample", [dataField("Bytes or file", "data", "encoding")]));
    stack.append(sectionBlock("Parameters", [
      numberField("Max lag", "maxLag", 32, 1, 256),
      numberField("Max key size", "maxKeySize", 40, 2, 256)
    ]));
    stack.append(actionRow("Profile sample"));
  } else if (id === "random") {
    stack.append(sectionBlock("Material", [
      selectField("Kind", "kind", ["bytes", "password"], "bytes"),
      numberField("Size", "size", 32, 1, 1048576),
      selectField("Output", "output", ["hex", "base64"], "hex")
    ]));
    stack.append(actionRow("Generate"));
  } else if (id === "xor") {
    stack.append(sectionBlock("Operands", [
      textField("Left", "left", "textarea"),
      textField("Right or key", "right", "textarea")
    ]));
    stack.append(sectionBlock("Parameters", [
      selectField("Mode", "mode", ["fixed", "repeating"], "fixed"),
      selectField("Input encoding", "encoding", ["hex", "base64", "text"], "hex"),
      selectField("Output", "output", ["hex", "base64", "text"], "hex")
    ]));
    stack.append(actionRow("Run XOR"));
  } else if (id === "keys") {
    stack.append(sectionBlock("Keypair", [readOnlyLine("Algorithm", "Ed25519")]));
    stack.append(actionRow("Generate Ed25519 pair"));
  } else if (id === "sign") {
    stack.append(sectionBlock("Private key", [textField("Private key PEM", "privatePem", "textarea")]));
    stack.append(sectionBlock("Message", [dataField("Message or file", "data", "encoding")]));
    stack.append(actionRow("Sign message"));
  } else if (id === "verify") {
    stack.append(sectionBlock("Public proof", [
      textField("Public key PEM", "publicPem", "textarea"),
      textField("Signature base64", "signature", "textarea")
    ]));
    stack.append(sectionBlock("Message", [dataField("Message or file", "data", "encoding")]));
    stack.append(actionRow("Verify signature"));
  } else if (id === "seal") {
    stack.append(sectionBlock("Envelope", [
      selectField("Operation", "sealAction", ["seal", "open"], "seal"),
      secretField("Passphrase", "passphrase")
    ]));
    stack.append(sectionBlock("Parameters", [
      numberField("PBKDF2 iterations", "iterations", 600000, 100000, 5000000),
      selectField("Open output", "output", ["base64", "text", "hex"], "base64")
    ]));
    stack.append(sectionBlock("Material", [dataField("Plaintext or sealed base64", "data", "encoding")]));
    stack.append(actionRow("Run seal operation"));
  }

  fragment.appendChild(stack);
  return fragment;
}

function sectionBlock(titleText, fields) {
  const section = document.createElement("section");
  section.className = "form-section";
  const heading = document.createElement("h2");
  heading.className = "section-title";
  heading.textContent = titleText;
  const body = document.createElement("div");
  body.className = "section-grid";
  for (const field of fields) {
    body.appendChild(field);
  }
  section.append(heading, body);
  return section;
}

function readOnlyLine(labelText, valueText) {
  const wrap = document.createElement("div");
  wrap.className = "field read-only-field";
  const label = document.createElement("span");
  label.className = "label";
  label.textContent = labelText;
  const value = document.createElement("span");
  value.className = "read-only-value";
  value.textContent = valueText;
  wrap.append(label, value);
  return wrap;
}

function hashOptions(values) {
  return values;
}

function dataField(labelText, dataId, encodingId) {
  const wrap = document.createElement("div");
  wrap.className = "wide-field";

  const header = fieldHeader(labelText, dataId, true);
  const meter = header.querySelector(".input-meter");
  wrap.appendChild(header);

  const drop = document.createElement("div");
  drop.className = "drop-row";

  const fileStatus = document.createElement("span");
  fileStatus.className = "file-status";
  fileStatus.textContent = "No file loaded";

  const dropActions = document.createElement("div");
  dropActions.className = "drop-actions";

  const clearButton = smallIconButton("Clear field", "clear");
  clearButton.addEventListener("click", () => {
    textarea.value = "";
    file.value = "";
    loadedValue = "";
    fileStatus.textContent = "No file loaded";
    refreshInputMeter(textarea, meter, encoding);
  });

  const fileLabel = document.createElement("label");
  fileLabel.className = "file-button";
  fileLabel.textContent = "Load file";
  const file = document.createElement("input");
  file.className = "hidden-file";
  file.type = "file";
  file.dataset.target = dataId;
  file.dataset.encoding = encodingId;
  fileLabel.appendChild(file);

  dropActions.append(clearButton, fileLabel);
  drop.append(fileStatus, dropActions);
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

  let loadedValue = "";
  const encodingSelect = encoding.querySelector("select");
  textarea.addEventListener("input", () => {
    if (!textarea.value) {
      fileStatus.textContent = "No file loaded";
    } else if (!loadedValue || textarea.value !== loadedValue) {
      fileStatus.textContent = "Manual buffer";
    }
    refreshInputMeter(textarea, meter, encoding);
  });
  encodingSelect.addEventListener("change", () => refreshInputMeter(textarea, meter, encoding));
  file.addEventListener("change", async () => {
    const selectedFile = file.files[0];
    if (!selectedFile) return;
    const bytes = new Uint8Array(await selectedFile.arrayBuffer());
    loadedValue = bytesToBase64(bytes);
    textarea.value = loadedValue;
    encodingSelect.value = "base64";
    fileStatus.textContent = `${selectedFile.name} | ${formatBytes(bytes.length)}`;
    refreshInputMeter(textarea, meter, encoding);
  });
  refreshInputMeter(textarea, meter, encoding);
  return wrap;
}

function textField(labelText, id, kind) {
  const wrap = document.createElement("div");
  wrap.className = "wide-field";
  const isTextarea = kind === "textarea";
  const header = fieldHeader(labelText, id, isTextarea);
  const input = kind === "textarea" ? document.createElement("textarea") : document.createElement("input");
  input.id = id;
  input.name = id;
  input.spellcheck = false;
  input.autocomplete = "off";
  wrap.append(header, input);
  if (isTextarea) {
    const meter = header.querySelector(".input-meter");
    const clearButton = header.querySelector(".small-icon-button");
    input.addEventListener("input", () => refreshTextMeter(input, meter));
    clearButton.addEventListener("click", () => {
      input.value = "";
      refreshTextMeter(input, meter);
    });
    refreshTextMeter(input, meter);
  }
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

function fieldHeader(labelText, id, withMeter) {
  const header = document.createElement("div");
  header.className = "field-header";
  const label = document.createElement("label");
  label.htmlFor = id;
  label.textContent = labelText;
  header.appendChild(label);
  if (withMeter) {
    const actions = document.createElement("div");
    actions.className = "field-actions";
    const meter = document.createElement("span");
    meter.className = "input-meter";
    meter.textContent = "0 bytes";
    actions.appendChild(meter);
    if (id !== "data") {
      actions.appendChild(smallIconButton("Clear field", "clear"));
    }
    header.appendChild(actions);
  }
  return header;
}

function smallIconButton(label, kind) {
  const button = document.createElement("button");
  button.className = "small-icon-button";
  button.type = "button";
  button.title = label;
  button.setAttribute("aria-label", label);
  button.appendChild(glyph(kind));
  return button;
}

function glyph(kind) {
  const span = document.createElement("span");
  span.className = `${kind}-glyph`;
  span.setAttribute("aria-hidden", "true");
  return span;
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

async function runActiveTool() {
  const payload = collectPayload();
  const endpoint = activeTool === "seal" && payload.sealAction === "open" ? "/api/open" : `/api/${activeTool}`;
  if (payload.sealAction) delete payload.sealAction;
  const payloadBytes = textBytes(JSON.stringify(payload));
  if (payloadBytes > maxClientPayloadBytes) {
    showError(new Error(`Request is ${formatBytes(payloadBytes)}; limit is ${formatBytes(maxClientPayloadBytes)}`));
    return;
  }
  setBusy(true);
  try {
    const result = await postJSON(endpoint, payload);
    showResult(result, activeTool);
    logActivity(`${tools.find((item) => item.id === activeTool).label} complete | ${formatBytes(payloadBytes)} request`);
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
  if (activeTool === "profile") {
    return { data: value("data"), encoding: value("encoding"), maxLag: Number(value("maxLag")), maxKeySize: Number(value("maxKeySize")) };
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
  lastPrimaryArtifact = primaryArtifact(data, toolId);
  output.textContent = lastResult;
  resultMeta.textContent = `${resultSummary(data, toolId)} | ${timeStamp()}`;
  renderResultSummary(data, toolId);
  renderChips(data, toolId);
  syncResultActions();
}

function showError(error) {
  const data = { error: error.message };
  lastResult = JSON.stringify(data, null, 2);
  lastPrimaryArtifact = null;
  output.textContent = lastResult;
  resultMeta.textContent = `Operation rejected | ${timeStamp()}`;
  renderSummaryItems([["Status", "Rejected"], ["Reason", error.message]], "bad");
  analysisStrip.textContent = "";
  const chip = document.createElement("span");
  chip.className = "chip bad";
  chip.textContent = "Rejected";
  analysisStrip.appendChild(chip);
  syncResultActions();
  logActivity("Operation rejected");
}

function renderReadyResult() {
  lastResult = `{
  "status": "ready",
  "scope": "local"
}`;
  lastPrimaryArtifact = null;
  output.textContent = lastResult;
  resultMeta.textContent = "Awaiting operation";
  renderSummaryItems([["Status", "Ready"], ["Scope", "Local process"], ["Output", "JSON"]]);
  analysisStrip.textContent = "";
  const chip = document.createElement("span");
  chip.className = "chip strong";
  chip.textContent = "Session guarded";
  analysisStrip.appendChild(chip);
  syncResultActions();
}

function clearResult() {
  renderReadyResult();
  logActivity("Result cleared");
}

function renderResultSummary(data, toolId) {
  if (toolId === "digest" || toolId === "hmac") {
    renderSummaryItems([
      ["Algorithm", data.algorithm.name],
      ["Input", `${data.size} bytes`],
      ["Strength", data.algorithm.deprecated ? "Deprecated" : `${data.algorithm.bits} bit`],
      [toolId === "digest" ? "Digest" : "MAC", data.hex, "mono"]
    ]);
  } else if (toolId === "entropy") {
    renderSummaryItems([
      ["Entropy", `${data.shannonBitsPerByte} bits/byte`],
      ["Unique", `${data.uniqueBytes} bytes`],
      ["Chi-square", String(data.chiSquare)],
      ["Assessment", data.assessment]
    ]);
  } else if (toolId === "profile") {
    renderSummaryItems([
      ["Assessment", data.assessment],
      ["Entropy", `${data.entropy.shannonBitsPerByte} bits/byte`],
      ["IOC", String(data.byteStats.normalizedCoincidence)],
      ["Signals", String(data.signals.length)]
    ]);
  } else if (toolId === "random") {
    renderSummaryItems(data.kind === "password" ? [
      ["Kind", "Password"],
      ["Length", `${data.length} chars`],
      ["Source", "CSPRNG"]
    ] : [
      ["Kind", "Bytes"],
      ["Size", `${data.size} bytes`],
      ["Encoding", data.encoding],
      ["Value", data.value, "mono"]
    ]);
  } else if (toolId === "xor") {
    renderSummaryItems([
      ["Size", `${data.size} bytes`],
      ["Encoding", data.encoding],
      ["Output", data.value, "mono"]
    ]);
  } else if (toolId === "keys") {
    renderSummaryItems([
      ["Algorithm", "Ed25519"],
      ["Public key", data.publicKeyBase64, "mono"],
      ["Private format", "PKCS#8 PEM"]
    ]);
  } else if (toolId === "sign") {
    renderSummaryItems([
      ["Algorithm", data.algorithm],
      ["Message", `${data.size} bytes`],
      ["Signature", data.signature, "mono"]
    ]);
  } else if (toolId === "verify") {
    renderSummaryItems([
      ["Verdict", data.valid ? "Valid" : "Invalid"],
      ["Algorithm", data.algorithm],
      ["Message", `${data.size} bytes`]
    ], data.valid ? "strong" : "bad");
  } else if (toolId === "seal") {
    renderSummaryItems(data.sealedSize ? [
      ["Envelope", data.info.algorithm],
      ["Input", `${data.inputSize} bytes`],
      ["Sealed", `${data.sealedSize} bytes`],
      ["KDF", data.info.kdf]
    ] : [
      ["Envelope", data.info.algorithm],
      ["Plaintext", `${data.plainSize} bytes`],
      ["KDF", data.info.kdf],
      ["Output", data.encoding]
    ]);
  } else {
    renderSummaryItems([["Status", "Complete"], ["Output", "JSON"]]);
  }
}

function renderSummaryItems(items, tone = "") {
  resultSummaryPanel.textContent = "";
  for (const [label, value, variant] of items) {
    const item = document.createElement("div");
    item.className = `summary-item ${tone}`.trim();
    const labelEl = document.createElement("span");
    labelEl.className = "summary-label";
    labelEl.textContent = label;
    const valueEl = document.createElement("span");
    valueEl.className = `summary-value ${variant || ""}`.trim();
    valueEl.textContent = value;
    item.append(labelEl, valueEl);
    resultSummaryPanel.appendChild(item);
  }
}

function primaryArtifact(data, toolId) {
  if (data.error) return null;
  if ((toolId === "digest" || toolId === "hmac") && data.hex) {
    return artifact(toolId === "digest" ? "Digest hex" : "MAC hex", data.hex, `sigil-${toolId}-${data.algorithm.name}.txt`);
  }
  if (toolId === "random") {
    if (data.kind === "password") {
      return artifact("Password", data.password, "sigil-password.txt");
    }
    return artifact("Random value", data.value, `sigil-random-${data.encoding || "hex"}.txt`);
  }
  if (toolId === "xor" && data.value) {
    return artifact("XOR output", data.value, `sigil-xor-${data.encoding}.txt`);
  }
  if (toolId === "profile") {
    return artifact("Profile report", JSON.stringify(data, null, 2), "sigil-profile.json");
  }
  if (toolId === "keys" && data.publicPem) {
    return artifact("Public key PEM", data.publicPem, "sigil-ed25519-public.pem");
  }
  if (toolId === "sign" && data.signature) {
    return artifact("Signature base64", data.signature, "sigil-signature.txt");
  }
  if (toolId === "verify") {
    return artifact("Verification verdict", data.valid ? "valid" : "invalid", "sigil-verify.txt");
  }
  if (toolId === "seal") {
    if (data.sealedBase64) return artifact("Sealed envelope", data.sealedBase64, "sigil-envelope.b64");
    if (data.output) return artifact("Opened output", data.output, `sigil-opened-${data.encoding || "base64"}.txt`);
  }
  return null;
}

function artifact(label, value, filename) {
  return { label, value, filename };
}

function toolIcon(kind) {
  const icon = document.createElement("span");
  icon.className = "tool-icon";
  icon.setAttribute("aria-hidden", "true");
  const svg = document.createElementNS("http://www.w3.org/2000/svg", "svg");
  svg.setAttribute("viewBox", "0 0 24 24");
  svg.setAttribute("focusable", "false");
  const shapes = iconShapes[kind] || iconShapes.hash;
  for (const shape of shapes) {
    const node = document.createElementNS("http://www.w3.org/2000/svg", shape.tag);
    for (const [name, value] of Object.entries(shape.attrs)) {
      node.setAttribute(name, value);
    }
    svg.appendChild(node);
  }
  icon.appendChild(svg);
  return icon;
}

const iconShapes = {
  hash: [
    { tag: "path", attrs: { d: "M8 4 6.5 20M17.5 4 16 20M4 9h16M3 15h16" } }
  ],
  mac: [
    { tag: "path", attrs: { d: "M7 11V8a5 5 0 0 1 10 0v3" } },
    { tag: "rect", attrs: { x: "5", y: "11", width: "14", height: "9", rx: "2" } },
    { tag: "path", attrs: { d: "M12 15v2" } }
  ],
  entropy: [
    { tag: "path", attrs: { d: "M4 17h16M6 17V9M12 17V5M18 17v-6" } },
    { tag: "circle", attrs: { cx: "6", cy: "7", r: "1.4" } },
    { tag: "circle", attrs: { cx: "12", cy: "3", r: "1.4" } },
    { tag: "circle", attrs: { cx: "18", cy: "9", r: "1.4" } }
  ],
  profile: [
    { tag: "path", attrs: { d: "M4 18V6M4 18h16" } },
    { tag: "path", attrs: { d: "M7 15c1.2-4 2.4-4 3.6 0s2.4 4 3.6 0 2.4-4 3.8-.5" } },
    { tag: "path", attrs: { d: "M7 9h10M7 12h4" } }
  ],
  xor: [
    { tag: "path", attrs: { d: "M6 6l12 12M18 6 6 18" } },
    { tag: "circle", attrs: { cx: "12", cy: "12", r: "8" } }
  ],
  random: [
    { tag: "rect", attrs: { x: "5", y: "5", width: "14", height: "14", rx: "3" } },
    { tag: "circle", attrs: { cx: "9", cy: "9", r: "1" } },
    { tag: "circle", attrs: { cx: "15", cy: "9", r: "1" } },
    { tag: "circle", attrs: { cx: "9", cy: "15", r: "1" } },
    { tag: "circle", attrs: { cx: "15", cy: "15", r: "1" } }
  ],
  key: [
    { tag: "circle", attrs: { cx: "8", cy: "8", r: "4" } },
    { tag: "path", attrs: { d: "m11 11 8 8M15 15l2-2M17 17l2-2" } }
  ],
  sign: [
    { tag: "path", attrs: { d: "M5 19h14M7 15l7.5-7.5a2.1 2.1 0 0 1 3 3L10 18H7v-3Z" } }
  ],
  verify: [
    { tag: "path", attrs: { d: "M20 7 10 17l-5-5" } },
    { tag: "path", attrs: { d: "M12 3.5 19 7v5c0 4.2-2.8 7.5-7 8.5-4.2-1-7-4.3-7-8.5V7l7-3.5Z" } }
  ],
  seal: [
    { tag: "path", attrs: { d: "M12 3.5 19 7v5c0 4.2-2.8 7.5-7 8.5-4.2-1-7-4.3-7-8.5V7l7-3.5Z" } },
    { tag: "path", attrs: { d: "M9 12h6M12 9v6" } }
  ]
};

function resultSummary(data, toolId) {
  if (data.error) return "Rejected";
  if (toolId === "digest" || toolId === "hmac") return `${data.algorithm.name} | ${data.size} bytes`;
  if (toolId === "entropy") return `${data.size} bytes | ${data.shannonBitsPerByte} bits per byte`;
  if (toolId === "profile") return `${data.size} bytes | ${data.assessment}`;
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
  } else if (toolId === "profile") {
    const keyCandidates = data.repeatKeyCandidates || [];
    chips.push(["strong", data.assessment]);
    chips.push([data.entropy.shannonBitsPerByte >= 7.75 ? "strong" : "warn", `${data.entropy.shannonBitsPerByte} bits per byte`]);
    chips.push(["", `IOC ${data.byteStats.normalizedCoincidence}`]);
    if (data.size >= 64 && keyCandidates.length && keyCandidates[0].normalizedHammingDistance <= 0.42) {
      chips.push(["warn", `key ${keyCandidates[0].keySize} hint`]);
    }
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

function syncResultActions() {
  const artifactLabel = lastPrimaryArtifact ? lastPrimaryArtifact.label : "";
  if (copyArtifactButton) {
    copyArtifactButton.disabled = !lastPrimaryArtifact;
    copyArtifactButton.title = lastPrimaryArtifact ? `Copy ${artifactLabel}` : "Copy primary output";
    copyArtifactButton.setAttribute("aria-label", copyArtifactButton.title);
  }
  if (saveButton) {
    saveButton.title = lastPrimaryArtifact ? `Save ${artifactLabel}` : "Download JSON";
    saveButton.setAttribute("aria-label", saveButton.title);
  }
}

async function copyPrimaryArtifact() {
  if (!lastPrimaryArtifact) {
    logActivity("No primary artifact");
    return;
  }
  await copyText(lastPrimaryArtifact.value, `${lastPrimaryArtifact.label} copied`, "Artifact copy unavailable");
}

async function copyResult() {
  await copyText(lastResult, "Full JSON copied", "Copy unavailable");
}

async function copyText(value, successMessage, failureMessage) {
  try {
    await navigator.clipboard.writeText(value);
    logActivity(successMessage);
  } catch {
    logActivity(failureMessage);
  }
}

function saveResult() {
  if (lastPrimaryArtifact) {
    downloadText(`${lastPrimaryArtifact.value}\n`, "text/plain", lastPrimaryArtifact.filename);
    logActivity(`${lastPrimaryArtifact.label} saved`);
    return;
  }
  downloadText(`${lastResult}\n`, "application/json", `sigil-${activeTool}-result.json`);
  logActivity("Result saved");
}

function downloadText(value, type, filename) {
  const blob = new Blob([value], { type });
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement("a");
  anchor.href = url;
  anchor.download = filename;
  document.body.appendChild(anchor);
  anchor.click();
  anchor.remove();
  URL.revokeObjectURL(url);
}

function refreshInputMeter(input, meter, encodingWrap) {
  const encoding = encodingWrap.querySelector("select").value;
  const estimate = estimateInputBytes(input.value, encoding);
  updateMeter(meter, estimate);
}

function refreshTextMeter(input, meter) {
  updateMeter(meter, { bytes: textBytes(input.value), label: `${formatBytes(textBytes(input.value))} text` });
}

function updateMeter(meter, estimate) {
  meter.textContent = estimate.label;
  meter.classList.toggle("bad", estimate.tone === "bad");
  meter.classList.toggle("warn", estimate.bytes > maxClientPayloadBytes * 0.8);
}

function estimateInputBytes(value, encoding) {
  if (!value) return { bytes: 0, label: "0 B" };
  if (encoding === "hex") {
    const clean = value.replace(/[\s:]/g, "");
    if (/[^0-9a-fA-F]/.test(clean)) return { bytes: 0, label: "invalid hex", tone: "bad" };
    if (clean.length % 2 !== 0) return { bytes: 0, label: "odd hex", tone: "bad" };
    const bytes = clean.length / 2;
    return { bytes, label: `${formatBytes(bytes)} hex` };
  }
  if (encoding === "base64") {
    const clean = value.trim();
    if (!/^[A-Za-z0-9+/]*={0,2}$/.test(clean) || clean.length % 4 === 1) {
      return { bytes: 0, label: "invalid base64", tone: "bad" };
    }
    const padding = clean.endsWith("==") ? 2 : clean.endsWith("=") ? 1 : 0;
    const bytes = Math.max(0, Math.floor((clean.length * 3) / 4) - padding);
    return { bytes, label: `${formatBytes(bytes)} base64` };
  }
  const bytes = textBytes(value);
  return { bytes, label: `${formatBytes(bytes)} text` };
}

function textBytes(value) {
  return textEncoder.encode(value).length;
}

function formatBytes(bytes) {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(bytes < 10240 ? 1 : 0)} KiB`;
  return `${(bytes / (1024 * 1024)).toFixed(bytes < 10 * 1024 * 1024 ? 1 : 0)} MiB`;
}

function timeStamp() {
  return new Date().toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" });
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
