const express = require("express");
const helmet = require("helmet");
const session = require("express-session");
const rateLimit = require("express-rate-limit");
const bcrypt = require("bcryptjs");
const path = require("path");

const app = express();
const PORT = Number(process.env.PORT || 3000);
const production = process.env.NODE_ENV === "production";

if (!process.env.SESSION_SECRET) {
  console.error("Missing SESSION_SECRET. Set a long random value in your environment.");
  process.exit(1);
}
if (!process.env.ACCESS_KEY_HASH) {
  console.error("Missing ACCESS_KEY_HASH. Create it with: npm run hash-key");
  process.exit(1);
}

app.disable("x-powered-by");
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      styleSrc: ["'self'"],
      scriptSrc: ["'self'"],
      imgSrc: ["'self'", "data:"],
      connectSrc: ["'self'"],
      objectSrc: ["'none'"],
      baseUri: ["'self'"],
      frameAncestors: ["'none'"]
    }
  }
}));
app.use(express.json({ limit: "10kb" }));
app.use(session({
  name: "moniroth.sid",
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    sameSite: "strict",
    secure: production,
    maxAge: 30 * 60 * 1000
  }
  // For production, configure a persistent session store (e.g. Redis);
  // Express's default MemoryStore is for local development only.
}));

const unlockLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 8,
  standardHeaders: "draft-7",
  legacyHeaders: false,
  message: { error: "Too many attempts. Wait 15 minutes and try again." }
});

app.post("/api/unlock", unlockLimiter, async (req, res) => {
  const key = typeof req.body?.key === "string" ? req.body.key.trim() : "";
  if (!key || key.length > 200) {
    return res.status(400).json({ error: "Enter a valid access key." });
  }

  try {
    const matches = await bcrypt.compare(key, process.env.ACCESS_KEY_HASH);
    if (!matches) {
      return res.status(401).json({ error: "That access key is not valid." });
    }
    req.session.authorized = true;
    return res.json({ ok: true, message: "Access granted." });
  } catch (err) {
    console.error("Key verification failed.");
    return res.status(500).json({ error: "Could not verify the key right now." });
  }
});

app.get("/api/status", (req, res) => {
  res.set("Cache-Control", "no-store");
  res.json({ authorized: req.session?.authorized === true });
});

app.post("/api/logout", (req, res) => {
  req.session.destroy(() => {
    res.clearCookie("moniroth.sid", {
      httpOnly: true,
      sameSite: "strict",
      secure: production
    });
    res.json({ ok: true });
  });
});

app.use(express.static(path.join(__dirname, "public"), {
  index: "index.html",
  etag: true,
  maxAge: production ? "1h" : 0
}));

app.listen(PORT, () => {
  console.log(`MONIROTH PROXY running on http://localhost:${PORT}`);
});
