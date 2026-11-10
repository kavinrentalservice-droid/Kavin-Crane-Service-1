
const express = require("express");
const crypto = require("crypto");

const app = express();
const PORT = process.env.PORT || 10000;

app.get("/", (req, res) => {
  res.status(200).send("Kavin Crane Service webhook is running");
});

app.get("/webhook", (req, res) => {
  const mode = req.query["hub.mode"];
  const token = req.query["hub.verify_token"];
  const challenge = req.query["hub.challenge"];

  if (
    mode === "subscribe" &&
    process.env.WHATSAPP_VERIFY_TOKEN &&
    token === process.env.WHATSAPP_VERIFY_TOKEN
  ) {
    return res.status(200).send(challenge);
  }

  return res.sendStatus(403);
});

app.post("/webhook", express.raw({
  type: "application/json",
  limit: "1mb"
}), (req, res) => {
  const secret = process.env.WHATSAPP_APP_SECRET;
  const signature = req.get("x-hub-signature-256");

  if (!secret || !signature ||
      !signature.startsWith("sha256=")) {
    return res.sendStatus(403);
  }

  const expected = crypto
    .createHmac("sha256", secret)
    .update(req.body)
    .digest();

  const supplied = Buffer.from(
    signature.slice(7), "hex"
  );

  if (
    supplied.length !== expected.length ||
    !crypto.timingSafeEqual(supplied, expected)
  ) {
    return res.sendStatus(403);
  }

  let payload;
  try {
    payload = JSON.parse(req.body.toString("utf8"));
  } catch {
    return res.sendStatus(400);
  }

  if (payload.object !== "whatsapp_business_account") {
    return res.sendStatus(404);
  }

  for (const entry of payload.entry || []) {
    for (const change of entry.changes || []) {
      const messages = change.value?.messages || [];
      console.log("Verified incoming messages:", messages.length);
    }
  }

  return res.sendStatus(200);
});

app.listen(PORT, "0.0.0.0", () => {
  console.log(`Webhook listening on port ${PORT}`);
});
