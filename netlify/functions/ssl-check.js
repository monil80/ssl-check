const tls = require("tls");
const net = require("net");

const WHOIS_SERVERS = {
  com: "whois.verisign-grs.com",
  net: "whois.verisign-grs.com",
  org: "whois.pir.org",
  io: "whois.nic.io",
  dev: "whois.nic.google",
  app: "whois.nic.google",
  co: "whois.nic.co",
  me: "whois.nic.me",
  info: "whois.afilias.net",
  biz: "whois.biz",
  in: "whois.registry.in",
  uk: "whois.nic.uk",
  de: "whois.denic.de",
  fr: "whois.nic.fr",
  au: "whois.auda.org.au",
  ca: "whois.cira.ca",
  ai: "whois.nic.ai",
};

function getWhoisServer(domain) {
  const parts = domain.split(".");
  const tld = parts[parts.length - 1].toLowerCase();
  return WHOIS_SERVERS[tld] || "whois.iana.org";
}

function whoisLookup(domain) {
  return new Promise((resolve) => {
    const server = getWhoisServer(domain);
    let data = "";

    const socket = net.connect(43, server, () => {
      socket.write(domain + "\r\n");
    });

    socket.setTimeout(8000);
    socket.on("data", (chunk) => { data += chunk.toString(); });

    socket.on("end", () => {
      const result = parseWhois(data);
      if (!result.creationDate && data.includes("Registrar WHOIS Server:")) {
        const match = data.match(/Registrar WHOIS Server:\s*(.+)/i);
        if (match) {
          const referralServer = match[1].trim();
          whoisReferral(domain, referralServer).then((ref) => {
            resolve(ref.creationDate ? ref : result);
          });
          return;
        }
      }
      resolve(result);
    });

    socket.on("timeout", () => { socket.destroy(); resolve({}); });
    socket.on("error", () => { resolve({}); });
  });
}

function whoisReferral(domain, server) {
  return new Promise((resolve) => {
    let data = "";
    const socket = net.connect(43, server, () => {
      socket.write(domain + "\r\n");
    });

    socket.setTimeout(6000);
    socket.on("data", (chunk) => { data += chunk.toString(); });
    socket.on("end", () => { resolve(parseWhois(data)); });
    socket.on("timeout", () => { socket.destroy(); resolve({}); });
    socket.on("error", () => { resolve({}); });
  });
}

function parseWhois(raw) {
  const result = {};
  const patterns = {
    domainName:       /Domain Name:\s*(.+)/i,
    registrar:        /Registrar:\s*(.+)/i,
    creationDate:     /Creat(?:ion|ed) Date:\s*(.+)/i,
    updatedDate:      /Updated Date:\s*(.+)/i,
    expiryDate:       /Expir(?:y|ation) Date:\s*(.+)/i,
    registrantOrg:    /Registrant Organization:\s*(.+)/i,
    nameServer:       /Name Server:\s*(.+)/i,
    status:           /Domain Status:\s*(\S+)/i,
  };

  for (const [key, regex] of Object.entries(patterns)) {
    const match = raw.match(regex);
    if (match) result[key] = match[1].trim();
  }

  const nsMatches = raw.match(/Name Server:\s*(.+)/gi);
  if (nsMatches) {
    result.nameServers = nsMatches
      .map((m) => m.replace(/Name Server:\s*/i, "").trim().toLowerCase())
      .filter((v, i, a) => a.indexOf(v) === i)
      .slice(0, 4);
  }

  return result;
}

function sslCheck(domain) {
  const startTime = Date.now();

  return new Promise((resolve) => {
    const timeout = setTimeout(() => {
      socket.destroy();
      resolve({ error: "Connection timed out", responseTimeMs: Date.now() - startTime });
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
          resolve({ error: "No certificate found", responseTimeMs });
          return;
        }

        const validFrom = new Date(cert.valid_from);
        const validTo = new Date(cert.valid_to);
        const now = Date.now();
        const daysRemaining = Math.floor((validTo - now) / (1000 * 60 * 60 * 24));
        const totalValidityDays = Math.floor((validTo - validFrom) / (1000 * 60 * 60 * 24));

        resolve({
          issuer: cert.issuer?.O || cert.issuer?.CN || "Unknown",
          subject: cert.subject?.CN || domain,
          validFrom: validFrom.toISOString(),
          validTo: validTo.toISOString(),
          daysRemaining,
          totalValidityDays,
          responseTimeMs,
          serialNumber: cert.serialNumber || "",
          fingerprint: cert.fingerprint256 || cert.fingerprint || "",
        });
      }
    );

    socket.on("error", (err) => {
      clearTimeout(timeout);
      resolve({ error: err.message, responseTimeMs: Date.now() - startTime });
    });
  });
}

exports.handler = async (event) => {
  const domain = event.queryStringParameters?.domain;

  if (!domain) {
    return {
      statusCode: 400,
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ error: "Missing domain" }),
    };
  }

  const [ssl, whois] = await Promise.all([sslCheck(domain), whoisLookup(domain)]);

  if (ssl.error) {
    return {
      statusCode: 500,
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ error: ssl.error, responseTimeMs: ssl.responseTimeMs, whois }),
    };
  }

  return {
    statusCode: 200,
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      domain,
      ...ssl,
      checkedAt: new Date().toISOString(),
      whois,
    }),
  };
};
