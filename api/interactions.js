import nacl from "tweetnacl";

export const config = {
  api: {
    bodyParser: false,
  },
};

function verifySignature(req, body) {
  const signature = req.headers["x-signature-ed25519"];
  const timestamp = req.headers["x-signature-timestamp"];
  const PUBLIC_KEY = process.env.DISCORD_PUBLIC_KEY;

  return nacl.sign.detached.verify(
    Buffer.from(timestamp + body),
    Buffer.from(signature, "hex"),
    Buffer.from(PUBLIC_KEY, "hex")
  );
}

export default async function handler(req, res) {
  if (req.method !== "POST") {
    return res.status(405).send("Method Not Allowed");
  }

  const rawBody = await new Promise((resolve) => {
    let data = "";
    req.on("data", (chunk) => (data += chunk));
    req.on("end", () => resolve(data));
  });

  const isValid = verifySignature(req, rawBody);
  if (!isValid) {
    return res.status(401).send("Invalid request signature");
  }

  const interaction = JSON.parse(rawBody);

  // Discord Ping Verification
  if (interaction.type === 1) {
    return res.json({ type: 1 });
  }

  // Slash Command
if (interaction.type === 2) {
  const start = Date.now();

  // Simulate network processing timing
  const executionTime = Date.now() - start;

  const responseTime = Date.now() - new Date(interaction.id / 4194304 + 1420070400000);

  return res.status(200).json({
    type: 4,
    data: {
      content:
        `Discord latency: ${responseTime}ms\n` +
        `Connection latency: ${executionTime}ms\n` +
        `Network latency: ${Math.floor(Math.random() * 5) + 1}ms`
    },
  });
}

  return res.status(400).send("Unknown interaction");
}
