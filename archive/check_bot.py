"""
check_bot.py — Verify Telegram bot connectivity.
Reads TELEGRAM_BOT_TOKEN and TELEGRAM_CHAT_ID from environment variables.
Set them in your shell or load your .env before running:
    export $(grep -v '^#' .env | xargs) && python check_bot.py
"""
import os
import urllib.request
import json

def check_bot():
    token   = os.environ.get("TELEGRAM_BOT_TOKEN", "")
    chat_id = os.environ.get("TELEGRAM_CHAT_ID", "")

    if not token:
        print("TELEGRAM_BOT_TOKEN not set. Export it first:")
        print("  export TELEGRAM_BOT_TOKEN=your_token_here")
        return

    print(f"Checking bot for token: {token[:10]}...")
    url = f"https://api.telegram.org/bot{token}/getMe"

    try:
        with urllib.request.urlopen(url, timeout=10) as resp:
            data = json.loads(resp.read())
        if data.get("ok"):
            bot_info = data["result"]
            print(f"Bot is ONLINE!")
            print(f"  Name    : {bot_info.get('first_name')}")
            print(f"  Username: @{bot_info.get('username')}")
            if chat_id:
                print(f"Chat ID  : {chat_id}")
            else:
                print("TELEGRAM_CHAT_ID not set — bot cannot send messages yet.")
        else:
            print(f"Bot API error: {data.get('description')}")
    except Exception as e:
        print(f"Connection error: {e}")

if __name__ == "__main__":
    check_bot()
