const express = require("express");
const cors = require("cors");
const dotenv = require("dotenv");
const helmet = require("helmet");
const dns = require("node:dns").promises;
const net = require("node:net");
const cheerio = require("cheerio");
const { createTelegramBot } = require("./telegram-bot");

dotenv.config();

const app = express();

const PORT = Number(process.env.PORT) || 5000;
const SEARXNG_URL = (
  process.env.SEARXNG_URL || "http://localhost:8080"
).replace(/\/$/, "");

const allowedOrigins = (process.env.ALLOWED_ORIGINS || "")
  .split(",")
  .map((origin) => origin.trim())
  .filter(Boolean);

const REQUEST_TIMEOUT_MS = 15000;
const MAX_RESPONSE_BYTES = 5 * 1024 * 1024;
const MAX_REDIRECTS = 5;
const telegramBotToken = process.env.TELEGRAM_BOT_TOKEN?.trim();
const telegramWebAppUrl = process.env.TELEGRAM_WEB_APP_URL?.trim();

app.use(
  cors({
    origin(origin, callback) {
      if (!origin || allowedOrigins.length === 0 || allowedOrigins.includes(origin)) {
        return callback(null, true);
      }

      return callback(new Error("Origin is not allowed"));
    },
  })
);
// The proxy response is intentionally embedded by the separate frontend
// origin. Its HTML response receives a more specific CSP below.
app.use(
  helmet({
    contentSecurityPolicy: false,
    frameguard: false,
  })
);
app.use(express.json({ limit: "100kb" }));

/* =========================================================
   BASIC TEST
========================================================= */

app.get("/api/test", (req, res) => {
  res.setHeader("Cache-Control", "no-store");

  res.json({
    success: true,
    message: "STARK Private Browser API is working!",
  });
});

app.get("/health", (req, res) => {
  res.json({ success: true, service: "stark-api" });
});

/* =========================================================
   IP / SSRF PROTECTION
========================================================= */

function isBlockedIp(address) {
  const version = net.isIP(address);

  if (version === 4) {
    const parts = address.split(".").map(Number);

    if (parts.length !== 4 || parts.some(Number.isNaN)) {
      return true;
    }

    const [a, b] = parts;

    // 0.0.0.0/8
    if (a === 0) return true;

    // 10.0.0.0/8
    if (a === 10) return true;

    // 127.0.0.0/8
    if (a === 127) return true;

    // 169.254.0.0/16
    if (a === 169 && b === 254) return true;

    // 172.16.0.0/12
    if (a === 172 && b >= 16 && b <= 31) {
      return true;
    }

    // 192.168.0.0/16
    if (a === 192 && b === 168) {
      return true;
    }

    // 100.64.0.0/10
    if (a === 100 && b >= 64 && b <= 127) {
      return true;
    }

    // 192.0.0.0/24
    if (a === 192 && b === 0) {
      return true;
    }

    // 198.18.0.0/15
    if (a === 198 && (b === 18 || b === 19)) {
      return true;
    }

    // 224.0.0.0/4 multicast
    if (a >= 224) {
      return true;
    }

    return false;
  }

  if (version === 6) {
    const normalized = address.toLowerCase();

    // IPv6 loopback
    if (normalized === "::1") {
      return true;
    }

    // IPv6 unspecified
    if (normalized === "::") {
      return true;
    }

    // IPv6 unique local addresses fc00::/7
    if (
      normalized.startsWith("fc") ||
      normalized.startsWith("fd")
    ) {
      return true;
    }

    // IPv6 link-local fe80::/10
    if (
      normalized.startsWith("fe8") ||
      normalized.startsWith("fe9") ||
      normalized.startsWith("fea") ||
      normalized.startsWith("feb")
    ) {
      return true;
    }

    // IPv4-mapped IPv6
    if (normalized.startsWith("::ffff:")) {
      const mapped = normalized.substring(7);

      if (net.isIP(mapped) === 4) {
        return isBlockedIp(mapped);
      }
    }
  }

  return false;
}

/* =========================================================
   URL VALIDATION
========================================================= */

async function validateTarget(rawUrl) {
  let target;

  try {
    target = new URL(rawUrl);
  } catch {
    throw new Error("Invalid URL");
  }

  // Only normal web protocols
  if (!["http:", "https:"].includes(target.protocol)) {
    throw new Error("Only HTTP and HTTPS are supported");
  }

  // Never allow embedded credentials
  if (target.username || target.password) {
    throw new Error("URLs containing credentials are blocked");
  }

  const hostname = target.hostname.toLowerCase();

  // Local hostnames
  if (
    hostname === "localhost" ||
    hostname.endsWith(".localhost") ||
    hostname === "local" ||
    hostname.endsWith(".local")
  ) {
    throw new Error("Local addresses are blocked");
  }

  // Direct IP
  if (net.isIP(hostname)) {
    if (isBlockedIp(hostname)) {
      throw new Error("Private or reserved IP addresses are blocked");
    }

    return target;
  }

  // Resolve DNS and check every result
  let addresses;

  try {
    addresses = await dns.lookup(hostname, {
      all: true,
      verbatim: true,
    });
  } catch {
    throw new Error("Unable to resolve destination");
  }

  if (!addresses.length) {
    throw new Error("Destination could not be resolved");
  }

  for (const item of addresses) {
    if (isBlockedIp(item.address)) {
      throw new Error("Destination resolves to a private or reserved address");
    }
  }

  return target;
}

/* =========================================================
   RESPONSE SIZE LIMIT
========================================================= */

async function readResponseLimited(response) {
  const contentLength = response.headers.get("content-length");

  if (contentLength) {
    const size = Number(contentLength);

    if (
      Number.isFinite(size) &&
      size > MAX_RESPONSE_BYTES
    ) {
      throw new Error("Response is too large");
    }
  }

  if (!response.body) {
    return Buffer.from(await response.arrayBuffer());
  }

  const reader = response.body.getReader();

  const chunks = [];
  let total = 0;

  while (true) {
    const { done, value } = await reader.read();

    if (done) break;

    total += value.byteLength;

    if (total > MAX_RESPONSE_BYTES) {
      try {
        await reader.cancel();
      } catch {}

      throw new Error("Response is too large");
    }

    chunks.push(Buffer.from(value));
  }

  return Buffer.concat(chunks);
}

/* =========================================================
   SAFE FETCH WITH REDIRECT VALIDATION
========================================================= */

async function fetchSafely(startUrl, options = {}) {
  let currentUrl = startUrl;

  for (let redirectCount = 0; redirectCount <= MAX_REDIRECTS; redirectCount++) {
    await validateTarget(currentUrl);

    const controller = new AbortController();

    const timeout = setTimeout(() => {
      controller.abort();
    }, REQUEST_TIMEOUT_MS);

    let response;

    try {
      response = await fetch(currentUrl, {
        method: options.method || "GET",

        headers: {
          "User-Agent":
            "Mozilla/5.0 (compatible; STARK-Private-Browser/1.0)",

          "Accept":
            options.accept ||
            "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",

          "Accept-Language": "en-US,en;q=0.8",

          // Never send browser cookies
          "Cookie": "",

          // Never send authorization from the client
          "Authorization": "",
        },

        redirect: "manual",

        signal: controller.signal,
      });
    } finally {
      clearTimeout(timeout);
    }

    // Redirect
    if (
      response.status >= 300 &&
      response.status < 400
    ) {
      const location = response.headers.get("location");

      if (!location) {
        return {
          response,
          finalUrl: currentUrl,
        };
      }

      const nextUrl = new URL(location, currentUrl).toString();

      currentUrl = nextUrl;

      continue;
    }

    return {
      response,
      finalUrl: currentUrl,
    };
  }

  throw new Error("Too many redirects");
}

/* =========================================================
   URL REWRITING
========================================================= */

function isDangerousProtocol(value) {
  const trimmed = String(value || "")
    .trim()
    .toLowerCase();

  return (
    trimmed.startsWith("javascript:") ||
    trimmed.startsWith("vbscript:") ||
    trimmed.startsWith("file:") ||
    trimmed.startsWith("ftp:") ||
    trimmed.startsWith("ws:") ||
    trimmed.startsWith("wss:")
  );
}

function proxyUrl(targetUrl, requestOrigin) {
  try {
    const parsed = new URL(targetUrl);

    if (
      !["http:", "https:"].includes(parsed.protocol)
    ) {
      return null;
    }

    return `${requestOrigin}/api/proxy?url=${encodeURIComponent(
      parsed.toString()
    )}`;
  } catch {
    return null;
  }
}

/* =========================================================
   REWRITE HTML
========================================================= */

function rewriteHtml(html, finalUrl, requestOrigin) {
  const $ = cheerio.load(html, {
    decodeEntities: false,
  });

  // Remove dangerous elements
  $("base").remove();

  // Remove meta refresh because it can bypass our navigation layer
  $('meta[http-equiv="refresh"]').remove();

  // Remove upstream CSP headers delivered inside HTML
  $('meta[http-equiv="Content-Security-Policy"]').remove();

  // Remove manifest references
  $('link[rel="manifest"]').remove();

  /* -----------------------------
     LINKS
  ----------------------------- */

  $("a[href]").each((_, element) => {
    const href = $(element).attr("href");

    if (!href) return;

    if (isDangerousProtocol(href)) {
      $(element).attr("href", "#");
      $(element).attr(
        "onclick",
        "return false;"
      );
      return;
    }

    if (
      href.startsWith("#") ||
      href.startsWith("mailto:") ||
      href.startsWith("tel:")
    ) {
      return;
    }

    try {
      const absolute = new URL(href, finalUrl);

      if (
        !["http:", "https:"].includes(
          absolute.protocol
        )
      ) {
        $(element).attr("href", "#");
        return;
      }

      const proxied = proxyUrl(
        absolute.toString(),
        requestOrigin
      );

      if (proxied) {
        $(element).attr("href", proxied);
        $(element).removeAttr("target");
      }
    } catch {
      $(element).attr("href", "#");
    }
  });

  /* -----------------------------
     IMAGES
  ----------------------------- */

  $("img[src]").each((_, element) => {
    const src = $(element).attr("src");

    if (!src || isDangerousProtocol(src)) {
      $(element).removeAttr("src");
      return;
    }

    try {
      const absolute = new URL(src, finalUrl);

      if (
        !["http:", "https:"].includes(
          absolute.protocol
        )
      ) {
        $(element).removeAttr("src");
        return;
      }

      const proxied = proxyUrl(
        absolute.toString(),
        requestOrigin
      );

      if (proxied) {
        $(element).attr("src", proxied);
      }
    } catch {
      $(element).removeAttr("src");
    }
  });

  /* -----------------------------
     SCRIPTS
  ----------------------------- */

  $("script[src]").each((_, element) => {
    const src = $(element).attr("src");

    if (!src || isDangerousProtocol(src)) {
      $(element).remove();
      return;
    }

    try {
      const absolute = new URL(src, finalUrl);

      if (
        !["http:", "https:"].includes(
          absolute.protocol
        )
      ) {
        $(element).remove();
        return;
      }

      const proxied = proxyUrl(
        absolute.toString(),
        requestOrigin
      );

      if (proxied) {
        $(element).attr("src", proxied);
      }
    } catch {
      $(element).remove();
    }
  });

  /* -----------------------------
     STYLESHEETS
  ----------------------------- */

  $('link[href]').each((_, element) => {
    const rel = (
      $(element).attr("rel") || ""
    ).toLowerCase();

    const href = $(element).attr("href");

    if (!href) return;

    // Only rewrite stylesheets
    if (!rel.includes("stylesheet")) {
      return;
    }

    if (isDangerousProtocol(href)) {
      $(element).remove();
      return;
    }

    try {
      const absolute = new URL(
        href,
        finalUrl
      );

      if (
        !["http:", "https:"].includes(
          absolute.protocol
        )
      ) {
        $(element).remove();
        return;
      }

      const proxied = proxyUrl(
        absolute.toString(),
        requestOrigin
      );

      if (proxied) {
        $(element).attr("href", proxied);
      }
    } catch {
      $(element).remove();
    }
  });

  /* -----------------------------
     FORMS
  ----------------------------- */

  $("form[action]").each((_, element) => {
    const action = $(element).attr("action");

    if (!action || isDangerousProtocol(action)) {
      $(element).attr("action", "#");
      return;
    }

    try {
      const absolute = new URL(
        action,
        finalUrl
      );

      if (
        !["http:", "https:"].includes(
          absolute.protocol
        )
      ) {
        $(element).attr("action", "#");
        return;
      }

      const proxied = proxyUrl(
        absolute.toString(),
        requestOrigin
      );

      if (proxied) {
        $(element).attr(
          "action",
          proxied
        );
      }
    } catch {
      $(element).attr("action", "#");
    }
  });

  /* -----------------------------
     IFRAMES
  ----------------------------- */

  $("iframe[src]").each((_, element) => {
    const src = $(element).attr("src");

    if (!src || isDangerousProtocol(src)) {
      $(element).remove();
      return;
    }

    try {
      const absolute = new URL(
        src,
        finalUrl
      );

      if (
        !["http:", "https:"].includes(
          absolute.protocol
        )
      ) {
        $(element).remove();
        return;
      }

      const proxied = proxyUrl(
        absolute.toString(),
        requestOrigin
      );

      if (proxied) {
        $(element).attr(
          "src",
          proxied
        );

        // Keep nested iframe isolated
        $(element).attr(
          "sandbox",
          "allow-forms allow-modals allow-popups allow-presentation allow-scripts"
        );
      }
    } catch {
      $(element).remove();
    }
  });

  /* -----------------------------
     INJECT BASE + PRIVACY META
  ----------------------------- */

  $("head").prepend(`
    <meta
      name="referrer"
      content="no-referrer"
    />

    <meta
      name="robots"
      content="noindex,nofollow,noarchive"
    />
  `);

  /*
     Prevent the proxied page from directly
     navigating the parent browser frame.
  */
  $("head").append(`
    <style>
      html {
        max-width: 100%;
      }

      body {
        max-width: 100%;
        overflow-x: auto;
      }
    </style>
  `);

  return $.html();
}

/* =========================================================
   SEARCH
========================================================= */

app.get("/api/search", async (req, res) => {
  const query = String(
    req.query.q || ""
  ).trim();

  const mode =
    req.query.mode === "images"
      ? "images"
      : "web";

  const safeSearch =
    req.query.safe === "false"
      ? 0
      : 2;

  if (!query) {
    return res.status(400).json({
      success: false,
      message: "Search query is required",
    });
  }

  if (query.length > 300) {
    return res.status(400).json({
      success: false,
      message: "Search query is too long",
    });
  }

  try {
    const categories =
      mode === "images"
        ? "images"
        : "general";

    const params =
      new URLSearchParams({
        q: query,
        format: "json",
        categories,
        safesearch: String(
          safeSearch
        ),
        language: "en",
      });

    const controller =
      new AbortController();

    const timeout = setTimeout(() => {
      controller.abort();
    }, REQUEST_TIMEOUT_MS);

    let response;

    try {
      response = await fetch(
        `${SEARXNG_URL}/search?${params.toString()}`,
        {
          headers: {
            Accept: "application/json",
          },
          signal: controller.signal,
        }
      );
    } finally {
      clearTimeout(timeout);
    }

    if (!response.ok) {
      throw new Error(
        `SearXNG returned ${response.status}`
      );
    }

    const data =
      await response.json();

    const results = (
      data.results || []
    ).map((result) => ({
      title:
        result.title || "",

      url:
        result.url || "",

      content:
        result.content || "",

      thumbnail:
        result.thumbnail ||
        result.img_src ||
        null,

      engine:
        result.engine || "",
    }));

    res.setHeader(
      "Cache-Control",
      "no-store, no-cache, must-revalidate, private"
    );

    res.json({
      success: true,
      query,
      mode,
      results,
    });
  } catch {
    // Intentionally do NOT log the search query.

    res.status(500).json({
      success: false,
      message:
        "Search service unavailable.",
    });
  }
});

/* =========================================================
   PRIVATE BROWSER PROXY
========================================================= */

app.get("/api/proxy", async (req, res) => {
  const rawUrl = String(
    req.query.url || ""
  ).trim();

  if (!rawUrl) {
    return res.status(400).send(
      "Missing URL"
    );
  }

  if (rawUrl.length > 4000) {
    return res.status(400).send(
      "URL is too long"
    );
  }

  try {
    const validated =
      await validateTarget(
        rawUrl
      );

    const {
      response,
      finalUrl,
    } = await fetchSafely(
      validated.toString()
    );

    const contentType =
      (
        response.headers.get(
          "content-type"
        ) || ""
      ).toLowerCase();

    res.setHeader(
      "Cache-Control",
      "no-store, no-cache, must-revalidate, private"
    );

    res.setHeader(
      "Pragma",
      "no-cache"
    );

    res.setHeader(
      "Expires",
      "0"
    );

    res.setHeader(
      "X-Robots-Tag",
      "noindex, nofollow, noarchive"
    );

    res.setHeader(
      "X-Content-Type-Options",
      "nosniff"
    );

    // Search results are rendered in a sandboxed iframe owned by the client.
    // Helmet's default SAMEORIGIN/frame-ancestors policy would block the
    // normal local setup (client:3000 -> API:5000) and separate Render hosts.
    res.removeHeader("X-Frame-Options");
    res.setHeader(
      "Content-Security-Policy",
      "default-src 'self' data: blob:; script-src 'self' 'unsafe-inline' 'unsafe-eval'; style-src 'self' 'unsafe-inline'; img-src 'self' data: blob:; font-src 'self' data:; connect-src 'self'; frame-src 'self'; frame-ancestors *"
    );

    res.setHeader(
      "X-STARK-Final-URL",
      finalUrl
    );

    /* -----------------------------------------
       HTML
    ----------------------------------------- */

    if (
      contentType.includes("text/html") ||
      contentType.includes("application/xhtml+xml")
    ) {
      const buffer =
        await readResponseLimited(
          response
        );

      const html =
        buffer.toString("utf8");

      const rewritten =
        rewriteHtml(
          html,
          finalUrl,
          `${req.protocol}://${req.get(
            "host"
          )}`
        );

      res.setHeader(
        "Content-Type",
        "text/html; charset=utf-8"
      );

      return res.send(
        rewritten
      );
    }

    /* -----------------------------------------
       CSS / JS / TEXT
    ----------------------------------------- */

    if (
      contentType.includes("text/css") ||
      contentType.includes("javascript") ||
      contentType.includes("application/json") ||
      contentType.includes("text/plain") ||
      contentType.includes("application/xml") ||
      contentType.includes("text/xml")
    ) {
      const buffer =
        await readResponseLimited(
          response
        );

      res.setHeader(
        "Content-Type",
        contentType
      );

      return res.send(buffer);
    }

    /* -----------------------------------------
       IMAGES / FONTS / MEDIA
    ----------------------------------------- */

    if (
      contentType.startsWith("image/") ||
      contentType.startsWith("font/") ||
      contentType.startsWith("audio/") ||
      contentType.startsWith("video/") ||
      contentType.includes(
        "application/font"
      ) ||
      contentType.includes(
        "application/octet-stream"
      )
    ) {
      const buffer =
        await readResponseLimited(
          response
        );

      res.setHeader(
        "Content-Type",
        contentType
      );

      return res.send(buffer);
    }

    /* -----------------------------------------
       Unsupported content
    ----------------------------------------- */

    return res.status(415).send(
      "STARK currently does not support this content type."
    );
  } catch (error) {
    const message =
      error instanceof Error
        ? error.message
        : "Proxy request failed";

    /*
      Do not log the actual URL.
      This is intentional because STARK
      should not create browsing-history logs.
    */

    res.status(400).send(
      `STARK could not load this page: ${message}`
    );
  }
});

/* =========================================================
   START SERVER
========================================================= */

app.listen(
  PORT,
  "0.0.0.0",
  () => {
    console.log(
      `STARK Private Browser API running on port ${PORT}`
    );

    if (telegramBotToken && telegramWebAppUrl) {
      const telegramBot = createTelegramBot({
        token: telegramBotToken,
        webAppUrl: telegramWebAppUrl,
      });

      telegramBot.start().catch((error) => {
        console.error("Telegram bot could not start:", error.message);
      });

      const stopTelegramBot = () => {
        telegramBot.stop();
      };

      process.once("SIGINT", stopTelegramBot);
      process.once("SIGTERM", stopTelegramBot);
    } else {
      console.log(
        "Telegram bot disabled: set TELEGRAM_BOT_TOKEN and TELEGRAM_WEB_APP_URL to enable it"
      );
    }
  }
);