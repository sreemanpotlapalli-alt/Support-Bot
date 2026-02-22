if (!req.headers["x-signature-ed25519"]) {
  // Allow manual testing
  const interaction = JSON.parse(rawBody);

  if (interaction.type === 1) {
    return res.json({ type: 1 });
  }

  return res.json({
    type: 4,
    data: { content: "Test mode active" },
  });
}
