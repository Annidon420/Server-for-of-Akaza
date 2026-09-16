const crypto = require("node:crypto");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");

const TELEGRAM_API_BASE = "https://api.telegram.org/bot";

function createTelegramBot({ token, webAppUrl }) {
  const apiUrl = `${TELEGRAM_API_BASE}${token}`;
  const lockName = crypto
    .createHash("sha256")
    .update(token)
    .digest("hex");
  const lockPath = path.join(
    os.tmpdir(),
    `stark-telegram-${lockName}.lock`
  );

  let updateOffset = 0;
  let polling = true;
  let pollingPromise;
  let activeRequest;
  let lockHandle;

  function releaseLock() {
    if (lockHandle === undefined) {
      return;
    }

    fs.closeSync(lockHandle);
    lockHandle = undefined;

    try {
      fs.unlinkSync(lockPath);
    } catch {}
  }

  function acquireLock() {
    try {
      lockHandle = fs.openSync(lockPath, "wx");
      fs.writeSync(lockHandle, `${process.pid}\n`);
      return;
    } catch (error) {
      if (error.code !== "EEXIST") {
        throw error;
      }
    }

    let ownerPid;

    try {
      ownerPid = Number(fs.readFileSync(lockPath, "utf8").trim());
      process.kill(ownerPid, 0);
    } catch (error) {
      if (error.code !== "ESRCH") {
        throw new Error(
          "Another STARK Telegram bot instance is already running"
        );
      }

      try {
        fs.unlinkSync(lockPath);
      } catch {}

      return acquireLock();
    }

    throw new Error(
      `Another STARK Telegram bot instance is already running (PID ${ownerPid})`
    );
  }

  async function callTelegram(method, payload = {}, signal) {
    const response = await fetch(`${apiUrl}/${method}`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify(payload),
      signal,
    });

    const data = await response.json();

    if (!response.ok || !data.ok) {
      throw new Error(data.description || `Telegram ${method} failed`);
    }

    return data.result;
  }

  async function sendWelcome(chatId) {
    return callTelegram("sendMessage", {
      chat_id: chatId,
      text: "Welcome to STARK Private Browser. Open a temporary private browsing session below.",
      reply_markup: {
        inline_keyboard: [[
          {
            text: "Open STARK",
            web_app: { url: webAppUrl },
          },
        ]],
      },
    });
  }

  async function handleUpdate(update) {
    const message = update.message;
    const text = message?.text?.trim();

    if (!message?.chat?.id || !text) {
      return;
    }

    if (text === "/start" || text === "/open" || text.startsWith("/start ")) {
      await sendWelcome(message.chat.id);
    }
  }

  async function poll() {
    while (polling) {
      try {
        activeRequest = new AbortController();
        const updates = await callTelegram("getUpdates", {
          offset: updateOffset,
          timeout: 25,
          allowed_updates: ["message"],
        }, activeRequest.signal);
        activeRequest = undefined;

        for (const update of updates) {
          updateOffset = update.update_id + 1;

          try {
            await handleUpdate(update);
          } catch (error) {
            console.error("Telegram update handling failed:", error.message);
          }
        }
      } catch (error) {
        activeRequest = undefined;

        if (!polling) {
          break;
        }

        if (
          error.message.includes(
            "Conflict: terminated by other getUpdates request"
          )
        ) {
          polling = false;
          releaseLock();
          console.error(
            "Telegram polling stopped: another instance is using this bot token"
          );
          break;
        }

        console.error("Telegram polling failed:", error.message);
        await new Promise((resolve) => setTimeout(resolve, 5000));
      }
    }
  }

  async function start() {
    acquireLock();

    try {
      await callTelegram("setMyCommands", {
        commands: [
          { command: "start", description: "Open STARK Private Browser" },
          { command: "open", description: "Open a private session" },
        ],
      });

      await callTelegram("setChatMenuButton", {
        menu_button: {
          type: "web_app",
          text: "Open STARK",
          web_app: { url: webAppUrl },
        },
      });

      console.log("STARK Telegram bot is running");
      pollingPromise = poll();
    } catch (error) {
      releaseLock();
      throw error;
    }
  }

  async function stop() {
    polling = false;
    activeRequest?.abort();

    if (pollingPromise) {
      await pollingPromise;
    }

    releaseLock();
  }

  return { start, stop };
}

module.exports = { createTelegramBot };
