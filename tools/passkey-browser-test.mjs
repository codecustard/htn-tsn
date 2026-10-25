// Run through tools/passkey-browser-test.sh, which starts the network this script drives.
import { createRequire } from "node:module";
import { spawn, execFileSync } from "node:child_process";
import { readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
const { chromium } = createRequire(join(process.cwd(), "noop.js"))("playwright");

const D = process.env.RUN_DIR + "/";
const BIN = process.env.BIN;
const master = JSON.parse(readFileSync(D + "master.pub.json", "utf8")).verifying_key;
const recovery = JSON.parse(readFileSync(D + "recovery.json", "utf8")).ed25519_public;
const bob = execFileSync(`${BIN}/tsn`, ["address", "--public", D + "master.pub.json", "--owner", D + "bob.json", "--name", "main", "--network", "kaspa-testnet"]).toString().trim();
const URL_ = `http://localhost:8080/examples/passkey.html?master=${master}&recovery=${recovery}`;
const browser = await chromium.launch();
let failed = false;
const check = (ok, what) => { console.log(`${ok ? "ok  " : "FAIL"} ${what}`); if (!ok) failed = true; };

async function device(name, credential) {
  const ctx = await browser.newContext(); // fresh storage = another device
  const page = await ctx.newPage();
  page.on("pageerror", (e) => console.log(`${name} pageerror:`, e.message));
  const cdp = await ctx.newCDPSession(page);
  await cdp.send("WebAuthn.enable");
  const { authenticatorId } = await cdp.send("WebAuthn.addVirtualAuthenticator", {
    options: { protocol: "ctap2", transport: "internal", hasResidentKey: true, hasUserVerification: true, isUserVerified: true, automaticPresenceSimulation: true },
  });
  if (credential) await cdp.send("WebAuthn.addCredential", { authenticatorId, credential }); // the synced passkey
  await page.goto(URL_);
  await page.fill("#url", "http://127.0.0.1:7190");
  await page.selectOption("#network", "kaspa-testnet");
  await page.click("#connect");
  await page.waitForSelector("#connect-out.ok", { timeout: 10000 });
  return { page, cdp, authenticatorId, ctx };
}
const text = (page, sel) => page.textContent(sel).then((t) => t.trim());

// Device A: create the wallet.
const A = await device("A");
await A.page.fill("#limit", "20");
await A.page.click("#create");
await A.page.waitForSelector("#wallet-out.ok", { timeout: 10000 });
const addr = await text(A.page, "#addr");
check((await text(A.page, "#status")) === "Ready", `A: created, status Ready, address ${addr}`);
console.log("     rules:", await text(A.page, "#rules"));
const policy = await A.page.textContent("#policy-json");
writeFileSync(D + "wallet.policy.json", policy);
const cliAddr = execFileSync(`${BIN}/tsn`, ["address", "--public", D + "master.pub.json", "--policy", D + "wallet.policy.json", "--name", "wallet", "--network", "kaspa-testnet"]).toString().trim();
check(cliAddr === addr, "A: page address matches the Rust CLI");
const script = execFileSync(`${BIN}/tsn`, ["address", "--public", D + "master.pub.json", "--policy", D + "wallet.policy.json", "--name", "wallet", "--network", "kaspa-testnet", "--script"]).toString().trim();
const mock = spawn("python3", ["tools/mock_api.py", "--port", "7299", "--address", addr, "--script", script, "--utxos", "5000000000", "--save", D + "submitted.json"], { stdio: "inherit" });
await new Promise((r) => setTimeout(r, 800));
const { credentials } = await A.cdp.send("WebAuthn.getCredentials", { authenticatorId: A.authenticatorId });
check(credentials.length === 1 && Buffer.from(credentials[0].userHandle, "base64").length === 58, "A: passkey carries the 58-byte wallet settings (B signs in without knowing its id)");

// Device B: the passkey synced; fresh browser. Sign in, find the wallet by balance, pay.
const B = await device("B", credentials[0]);
await B.page.click("#signin");
await B.page.waitForSelector("#wallet-out.ok", { timeout: 10000 });
await B.page.waitForFunction(() => document.getElementById("balance").textContent.includes("50"), null, { timeout: 10000 });
check((await text(B.page, "#status")) === "Signed in (found by balance)", `B: signed in with one prompt, balance ${await text(B.page, "#balance")}`);
check((await text(B.page, "#rules")).includes("up to 20 KAS"), "B: settings came back from the passkey");

async function pay(page, amount) {
  await page.fill("#to", bob);
  await page.fill("#amount", amount);
  await page.click("#send");
  await page.waitForSelector("#review:not([hidden])", { timeout: 15000 });
  await page.click("#approve");
  await page.waitForFunction(() => /ok|bad/.test(document.getElementById("send-out").className), null, { timeout: 30000 });
  return { cls: await page.getAttribute("#send-out", "class"), out: await text(page, "#send-out") };
}
let r = await pay(B.page, "25");
check(r.cls === "bad" && r.out.includes("limit 2000000000"), `B: 25 KAS refused by nodes: ${r.out.slice(0, 90)}…`);
check((await text(B.page, "#status")) === "Ready" && (await text(B.page, "#addr")) === addr, "B: that approval settled the key; address matches A");
r = await pay(B.page, "10");
check(r.cls === "ok" && r.out.includes("txid"), `B: 10 KAS paid: ${r.out.split("\n").pop()}`);

// Device C: sign in, then confirm explicitly to see the deposit address.
const C = await device("C", credentials[0]);
await C.page.click("#signin");
await C.page.waitForSelector("#wallet-out.ok", { timeout: 10000 });
check(!(await C.page.isHidden("#confirm")), "C: deposit address hidden until confirmed");
await C.page.click("#confirm");
await C.page.waitForSelector("#wallet-out.ok", { timeout: 10000 });
check((await text(C.page, "#addr")) === addr, "C: confirmed address matches A");

// Device D: a passkey that isn't a wallet passkey.
const D2 = await device("D");
await D2.page.evaluate(async () => {
  await navigator.credentials.create({ publicKey: { rp: { id: "localhost", name: "x" }, user: { id: new Uint8Array(16), name: "x", displayName: "x" }, challenge: new Uint8Array(32), pubKeyCredParams: [{ type: "public-key", alg: -7 }], authenticatorSelection: { residentKey: "required", userVerification: "required" } } });
});
await D2.page.click("#signin");
await D2.page.waitForSelector("#wallet-out.bad", { timeout: 10000 });
check((await text(D2.page, "#wallet-out")).includes("not created as an htn-tsn wallet"), "D: foreign passkey rejected with a clear message");

mock.kill();
await browser.close();
console.log(failed ? "FAILED" : "PASSED");
process.exit(failed ? 1 : 0);
