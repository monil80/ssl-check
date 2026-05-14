const tls = require("tls");

exports.handler = async (event) => {
  const domain = event.queryStringParameters?.domain;

  if (!domain) {
    return {
      statusCode: 400,
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ error: "Missing domain" }),
    };
  }

  const startTime = Date.now();

  return new Promise((resolve) => {
    const timeout = setTimeout(() => {
      socket.destroy();
      resolve({
        statusCode: 504,
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ error: "Connection timed out", responseTimeMs: Date.now() - startTime }),
      });
    }, 10000);

    const socket = tls.connect(
      443,
      domain,
      { servername: domain, rejectUnauthorized: false },
      () => {
        clearTimeout(timeout);
        const cert = socket.getPeerCertificate();
        socket.end();

        const responseTimeMs = Date.now() - startTime;

        if (!cert || !cert.valid_to) {
          resolve({
            statusCode: 500,
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ error: "No certificate found", responseTimeMs }),
          });
          return;
        }

        const validFrom = new Date(cert.valid_from);
        const validTo = new Date(cert.valid_to);
        const now = Date.now();
        const daysRemaining = Math.floor((validTo - now) / (1000 * 60 * 60 * 24));
        const totalValidityDays = Math.floor((validTo - validFrom) / (1000 * 60 * 60 * 24));

        resolve({
          statusCode: 200,
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            domain,
            issuer: cert.issuer?.O || cert.issuer?.CN || "Unknown",
            subject: cert.subject?.CN || domain,
            validFrom: validFrom.toISOString(),
            validTo: validTo.toISOString(),
            daysRemaining,
            totalValidityDays,
            responseTimeMs,
            checkedAt: new Date().toISOString(),
            serialNumber: cert.serialNumber || "",
            fingerprint: cert.fingerprint256 || cert.fingerprint || "",
          }),
        });
      }
    );

    socket.on("error", (err) => {
      clearTimeout(timeout);
      resolve({
        statusCode: 500,
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ error: err.message, responseTimeMs: Date.now() - startTime }),
      });
    });
  });
};
