import telegram
from telegram import InlineKeyboardButton, InlineKeyboardMarkup, Update
from telegram.ext import Application, CommandHandler, CallbackQueryHandler, MessageHandler, filters
from telethon.sync import TelegramClient
from telethon.tl.functions.messages import GetDialogsRequest
from telethon.tl.types import InputPeerEmpty
import sqlite3
import os
import re
import json
import logging
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import base64
import asyncio
from aiohttp import web

# Настройка логирования
logging.basicConfig(filename='bot_logs.log', level=logging.INFO, 
                    format='%(asctime)s - %(levelname)s - %(message)s')

# Токен бота
TOKEN = "7585246759:AAEJMLF64kQFqke2m_ZMX3OwwPxV-pBziIQ"
# API для Telethon
API_ID = 25044500
API_HASH = "6358722d94915793a344196c42cfdd9"
# Пароль для админки
ADMIN_PASSWORD = "U2h7t919k@%2840+]×0294&'n₩|◇•¡▪︎♤2910"
# Путь к базе данных SQLite
DB_PATH = "alotof_data.db"
# Ключ для шифрования (генерируется один раз, сохрани его!)
ENCRYPTION_KEY = get_random_bytes(16)  # 16 байт для AES-128

# Инициализация Telethon
client = TelegramClient('session', API_ID, API_HASH)

# Шифрование данных
def encrypt_data(data):
    cipher = AES.new(ENCRYPTION_KEY, AES.MODE_EAX)
    nonce = cipher.nonce
    ciphertext, tag = cipher.encrypt_and_digest(data.encode())
    return base64.b64encode(nonce + ciphertext).decode()

# Дешифрование данных
def decrypt_data(encrypted_data):
    raw = base64.b64decode(encrypted_data.encode())
    nonce = raw[:16]
    ciphertext = raw[16:]
    cipher = AES.new(ENCRYPTION_KEY, AES.MODE_EAX, nonce=nonce)
    return cipher.decrypt(ciphertext).decode()

# Валидация ввода
def validate_input(mode, value):
    if mode == 'phone' and not re.match(r'^\+\d{10,15}$', value):
        return False, "Номер телефона должен быть в формате +79991234567"
    if mode == 'email' and not re.match(r'^[\w\.-]+@[\w\.-]+\.\w+$', value):
        return False, "Email должен быть в формате user@example.com"
    if mode == 'ip' and not re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', value):
        return False, "IP должен быть в формате 192.168.1.1"
    return True, None

# Инициализация SQLite
def init_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS users 
                 (id INTEGER PRIMARY KEY, phone TEXT, username TEXT, email TEXT, ip TEXT, chats TEXT)''')
    conn.commit()
    conn.close()

# Загрузка данных из файла (без pandas)
def load_data(file_path):
    data = []
    if file_path.endswith('.csv'):
        with open(file_path, 'r') as f:
            lines = f.readlines()
            headers = lines[0].strip().split(',')
            for line in lines[1:]:
                values = line.strip().split(',')
                data.append(dict(zip(headers, values)))
    elif file_path.endswith('.json'):
        with open(file_path, 'r') as f:
            data = json.load(f)
    elif file_path.endswith('.txt'):
        with open(file_path, 'r') as f:
            lines = f.readlines()
            headers = lines[0].strip().split('\t')
            for line in lines[1:]:
                values = line.strip().split('\t')
                data.append(dict(zip(headers, values)))
    return data

# Сохранение данных в SQLite с шифрованием
def save_to_db(data):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    for row in data:
        chats = encrypt_data(row.get('chats', ''))
        c.execute("INSERT OR IGNORE INTO users (id, phone, username, email, ip, chats) VALUES (?, ?, ?, ?, ?, ?)",
                  (row.get('id'), row.get('phone'), row.get('username'), row.get('email'), row.get('ip'), chats))
    conn.commit()
    conn.close()

# Команда /start
async def start(update: Update, context):
    keyboard = [
        [InlineKeyboardButton("📱 Поиск по номеру телефона", callback_data='phone')],
        [InlineKeyboardButton("🆔 Поиск по ID", callback_data='id')],
        [InlineKeyboardButton("👤 Поиск по username", callback_data='username')],
        [InlineKeyboardButton("📧 Поиск по email", callback_data='email')],
        [InlineKeyboardButton("🌐 Поиск по IP", callback_data='ip')],
        [InlineKeyboardButton("💬 Чаты пользователя", callback_data='chats')],
        [InlineKeyboardButton("🔍 Мультипоиск", callback_data='multi')],
        [InlineKeyboardButton("⚙️ Добавить базу (Админ)", callback_data='admin')]
    ]
    reply_markup = InlineKeyboardMarkup(keyboard)
    await update.message.reply_text(
        "🔥 *ALotOf (ALO)* — твой хакерский помощник! 🔥\n"
        "Выбери опцию, чтобы разъебать систему:\n"
        "💡 Используй /help для инструкций.",
        reply_markup=reply_markup, parse_mode='Markdown'
    )
    logging.info(f"User {update.message.from_user.id} started the bot")

# Команда /help
async def help_command(update: Update, context):
    await update.message.reply_text(
        "📚 *Инструкция по использованию ALotOf (ALO)* 📚\n\n"
        "1️⃣ *Поиск*: Выбери опцию (телефон, ID, username и т.д.) и введи данные.\n"
        "   - Телефон: в формате +79991234567\n"
        "   - Email: в формате user@example.com\n"
        "   - IP: в формате 192.168.1.1\n"
        "2️⃣ *Мультипоиск*: Введи несколько параметров, например:\n"
        "   `phone:+7999 username:user1`\n"
        "3️⃣ *Чаты*: Укажи username или ID, чтобы узнать, в каких чатах был пользователь.\n"
        "4️⃣ *Админка*: Для добавления базы выбери 'Добавить базу', введи пароль и загрузи файл (CSV, TXT, JSON).\n\n"
        "💥 Всё бесплатно, никаких подписок! Разъёб полный!",
        parse_mode='Markdown'
    )

# Парсинг чатов через Telethon
async def get_user_chats(identifier):
    await client.start()
    dialogs = await client(GetDialogsRequest(
        offset_date=None,
        offset_id=0,
        offset_peer=InputPeerEmpty(),
        limit=200,
        hash=0
    ))
    chats = []
    for dialog in dialogs.chats:
        chats.append(dialog.title)
    return ", ".join(chats) if chats else "Чатов не найдено"

# Обработка кнопок
async def button(update: Update, context):
    query = update.callback_query
    await query.answer()
    option = query.data

    if option == 'admin':
        await query.edit_message_text("🔒 Введите пароль для доступа к админ-панели:")
        context.user_data['mode'] = 'admin_password'
    elif option == 'multi':
        await query.edit_message_text("Введите данные для мультипоиска (например: phone:+7999 username:user1):")
        context.user_data['mode'] = 'multi'
    else:
        await query.edit_message_text(f"Введите {option} для поиска:")
        context.user_data['mode'] = option

# Обработка текстовых сообщений
async def handle_message(update: Update, context):
    text = update.message.text
    mode = context.user_data.get('mode')
    user_id = update.message.from_user.id

    if mode == 'admin_password':
        if text == ADMIN_PASSWORD:
            await update.message.reply_text("✅ Пароль верный. Пришлите файл базы данных (CSV, TXT, JSON):")
            context.user_data['mode'] = 'admin_upload'
        else:
            await update.message.reply_text("❌ Неверный пароль, вали отсюда, дебил.")
            context.user_data['mode'] = None
    elif mode == 'admin_upload':
        await update.message.reply_text("Файл пока не поддерживается через текст. Используй /upload для загрузки.")
        context.user_data['mode'] = None
    elif mode == 'multi':
        params = dict(re.findall(r'(\w+):(\S+)', text))
        if not params:
            await update.message.reply_text("❌ Введи данные в формате: phone:+7999 username:user1")
            return
        result = multi_search(params)
        await update.message.reply_text(result, parse_mode='Markdown')
        logging.info(f"User {user_id} performed multi-search: {params}")
        context.user_data['mode'] = None
    elif mode in ['phone', 'id', 'username', 'email', 'ip', 'chats']:
        # Валидация ввода
        if mode in ['phone', 'email', 'ip']:
            is_valid, error = validate_input(mode, text)
            if not is_valid:
                await update.message.reply_text(f"❌ {error}")
                return

        if mode == 'chats':
            chats = await get_user_chats(text)
            result = f"💬 *Чаты пользователя* 💬\n━━━━━━━━━━━━━━━\n{chats}\n━━━━━━━━━━━━━━━"
        else:
            result = search_in_db(mode, text)
        await update.message.reply_text(result, parse_mode='Markdown')
        logging.info(f"User {user_id} searched {mode}: {text}")
        context.user_data['mode'] = None

# Поиск в базе
def search_in_db(mode, value):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    if mode == 'phone':
        c.execute("SELECT * FROM users WHERE phone = ?", (value,))
    elif mode == 'id':
        c.execute("SELECT * FROM users WHERE id = ?", (value,))
    elif mode == 'username':
        c.execute("SELECT * FROM users WHERE username = ?", (value,))
    elif mode == 'email':
        c.execute("SELECT * FROM users WHERE email = ?", (value,))
    elif mode == 'ip':
        c.execute("SELECT * FROM users WHERE ip = ?", (value,))
    
    result = c.fetchone()
    conn.close()

    if result:
        chats = decrypt_data(result[5]) if result[5] else "Нет данных"
        return (
            f"🔍 *Результат поиска* 🔍\n"
            f"━━━━━━━━━━━━━━━\n"
            f"🆔 ID: {result[0]}\n"
            f"📱 Phone: {result[1]}\n"
            f"👤 Username: {result[2]}\n"
            f"📧 Email: {result[3]}\n"
            f"🌐 IP: {result[4]}\n"
            f"💬 Chats: {chats}\n"
            f"━━━━━━━━━━━━━━━"
        )
    return "❌ Ничего не найдено, сука."

# Мультипоиск
def multi_search(params):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    query = "SELECT * FROM users WHERE " + " AND ".join(f"{k} = ?" for k in params.keys())
    c.execute(query, list(params.values()))
    result = c.fetchone()
    conn.close()

    if result:
        chats = decrypt_data(result[5]) if result[5] else "Нет данных"
        return (
            f"🔍 *Результат мультипоиска* 🔍\n"
            f"━━━━━━━━━━━━━━━\n"
            f"🆔 ID: {result[0]}\n"
            f"📱 Phone: {result[1]}\n"
            f"👤 Username: {result[2]}\n"
            f"📧 Email: {result[3]}\n"
            f"🌐 IP: {result[4]}\n"
            f"💬 Chats: {chats}\n"
            f"━━━━━━━━━━━━━━━"
        )
    return "❌ Ничего не найдено, дебил."

# Загрузка файла
async def handle_file(update: Update, context):
    if context.user_data.get('mode') != 'admin_upload':
        await update.message.reply_text("❌ Ты не админ, вали отсюда.")
        return
    
    file = update.message.document
    file_path = f"uploads/{file.file_name}"
    os.makedirs("uploads", exist_ok=True)
    await file.download_to_drive(file_path)
    
    data = load_data(file_path)
    if data:
        save_to_db(data)
        await update.message.reply_text(f"✅ База {file.file_name} загружена, пиздец как круто!")
    else:
        await update.message.reply_text("❌ Формат файла — хуйня, попробуй ещё раз.")
    
    context.user_data['mode'] = None

# Webhook handler
app = Application.builder().token(TOKEN).build()

async def webhook(request):
    update = Update.de_json(await request.json(), app.bot)
    await app.process_update(update)
    return web.Response(text="OK")

# Инициализация бота
def main():
    init_db()
    app.add_handler(CommandHandler("start", start))
    app.add_handler(CommandHandler("help", help_command))
    app.add_handler(CallbackQueryHandler(button))
    app.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, handle_message))
    app.add_handler(MessageHandler(filters.Document.ALL, handle_file))

    # Запуск веб-сервера для webhook
    web_app = web.Application()
    web_app.router.add_post(f"/{TOKEN}", webhook)
    web.run_app(web_app, host="0.0.0.0", port=int(os.getenv("PORT", 8443)))

if __name__ == "__main__":
    main()