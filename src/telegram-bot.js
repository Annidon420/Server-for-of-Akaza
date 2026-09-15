const TELEGRAM_API_BASE = "https://api.telegram.org/bot";

function createTelegramBot({ token, webAppUrl }) {
  const apiUrl = `${TELEGRAM_API_BASE}${token}`;
  let updateOffset = 0;
  let polling = true;

  async function callTelegram(method, payload = {}) {
    const response = await fetch(`${apiUrl}/${method}`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify(payload),
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
        const updates = await callTelegram("getUpdates", {
          offset: updateOffset,
          timeout: 25,
          allowed_updates: ["message"],
        });

        for (const update of updates) {
          updateOffset = update.update_id + 1;

          try {
            await handleUpdate(update);
          } catch (error) {
            console.error("Telegram update handling failed:", error.message);
          }
        }
      } catch (error) {
        console.error("Telegram polling failed:", error.message);
        await new Promise((resolve) => setTimeout(resolve, 5000));
      }
    }
  }

  async function start() {
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
    void poll();
  }

  function stop() {
    polling = false;
  }

  return { start, stop };
}

module.exports = { createTelegramBot };
