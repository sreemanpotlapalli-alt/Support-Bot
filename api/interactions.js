import nacl from "tweetnacl";

export const config = {
  api: {
    bodyParser: false,
  },
};

async function getRawBody(req) {
  return new Promise((resolve, reject) => {
    let data = "";
    req.on("data", (chunk) => (data += chunk));
    req.on("end", () => resolve(data));
    req.on("error", (err) => reject(err));
  });
}

function verifySignature(rawBody, signature, timestamp, publicKey) {
  try {
    return nacl.sign.detached.verify(
      Buffer.from(timestamp + rawBody),
      Buffer.from(signature, "hex"),
      Buffer.from(publicKey, "hex")
    );
  } catch {
    return false;
  }
}

export default async function handler(req, res) {
  try {
    if (req.method !== "POST") {
      return res.status(405).end();
    }

    const rawBody = await getRawBody(req);

    const signature = req.headers["x-signature-ed25519"];
    const timestamp = req.headers["x-signature-timestamp"];
    const publicKey = process.env.DISCORD_PUBLIC_KEY;

    if (!signature || !timestamp || !publicKey) {
      return res.status(401).end();
    }

    const isValid = verifySignature(
      rawBody,
      signature,
      timestamp,
      publicKey
    );

    if (!isValid) {
      return res.status(401).end();
    }

    const interaction = JSON.parse(rawBody);

    // Discord verification ping
    if (interaction.type === 1) {
      return res.status(200).json({ type: 1 });
    }

    // Slash command
    if (interaction.type === 2) {
      if (interaction.data.name === "ping") {

        const now = Date.now();

        // Discord snowflake timestamp extraction
        const discordTimestamp =
          Number(BigInt(interaction.id) >> 22n) + 1420070400000;

        const latency = now - discordTimestamp;

        return res.status(200).json({
          type: 4,
          data: {
            content: `Ping?\nPong! Took ${latency}ms.`,
          },
        });
      }
    }

    return res.status(400).end();

  } catch (err) {
    console.error("Interaction Error:", err);
    return res.status(500).end();
  }
}
