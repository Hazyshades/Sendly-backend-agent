import logging
import os
import sys
import tempfile
from typing import Optional

import aiofiles
from telegram import Update
from telegram.ext import Application, CommandHandler, ContextTypes, MessageHandler, filters

from agent.graph import create_agent_graph
from agent.tools import supabase_service
from config.settings import settings
from services.elevenlabs_service import elevenlabs_service

logging.basicConfig(
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    level=logging.INFO
)

logger = logging.getLogger(__name__)


agent_graph = None


async def ensure_agent_graph() -> None:
    global agent_graph

    if agent_graph is None:
        agent_graph = create_agent_graph()
        logger.info("Agent graph initialized")


async def invoke_agent(
    user_id: str,
    raw_input: str,
    message_type: str,
    extra_state: Optional[dict] = None
) -> dict:
    await ensure_agent_graph()

    contacts = await supabase_service.get_contacts(user_id)

    initial_state = {
        'user_id': user_id,
        'message_type': message_type,
        'raw_input': raw_input,
        'blockchain': settings.DEFAULT_BLOCKCHAIN,
        'fee_level': 'MEDIUM',
        'testnet_tokens_requested': False,
        'response': '',
        'contacts': contacts
    }

    if extra_state:
        initial_state.update(extra_state)

    result = await agent_graph.ainvoke(initial_state)
    return result


async def start_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """
    Handler for the /start command.
    """
    await update.message.reply_text(
        "👋 Hello! I am the Sendly AI agent.\n\n"
        "⚙️ I can help you with:\n"
        "- Checking balances\n"
        "- Sending transactions\n"
        "- Requesting test tokens\n"
        "- Processing voice commands\n\n"
        "✍️ Describe what you need or send a voice message.\n"
        "📋 Use /voice_help to see sample voice scenarios."
    )


async def help_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """
    Handler for the /help command.
    """
    await update.message.reply_text(
        "📖 Bot Help\n\n"
        "Available actions:\n"
        "1. Balance check - \"Show my wallet balance\"\n"
        "2. Transactions - \"Send 10 USDC to address 0x...\"\n"
        "3. Test tokens - \"Request test USDC for me\"\n"
        "4. Contact management - /addcontact, /listcontacts, /deletecontact\n"
        "5. Voice commands - see /voice_help\n\n"
        "Describe what you need in simple words and I will handle the rest."
    )


async def handle_message(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """
    Handler for incoming text messages.
    """
    user_id = str(update.effective_user.id)
    user_message = update.message.text
    
    logger.info(f"Received message from user {user_id}: {user_message}")
    
    await update.message.reply_text("⏳ Processing your request...")
    
    try:
        result = await invoke_agent(
            user_id=user_id,
            raw_input=user_message,
            message_type='text'
        )
        
        response_text = result.get('response', 'Action completed.')
        
        if result.get('error'):
            response_text = f"❌ Error: {result['error']}\n\n{response_text}"
        else:
            response_text = f"✅ {response_text}"
        
        await update.message.reply_text(response_text)
        
        logger.info(f"Response sent to user {user_id}")
    
    except Exception as e:
        logger.error(f"Error while processing user message: {e}", exc_info=True)
        await update.message.reply_text(
            f"❌ An error occurred while processing the command:\n{str(e)}\n\n"
            "Try rephrasing the request or use /help."
        )


async def handle_voice_message(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_id = str(update.effective_user.id)

    if not update.message or not update.message.voice:
        await update.effective_message.reply_text("❌ Failed to retrieve the voice message.")
        return

    logger.info("Received voice message from user %s", user_id)

    voice_file = await context.bot.get_file(update.message.voice.file_id)

    temp_file = tempfile.NamedTemporaryFile(delete=False, suffix=".oga")
    temp_path = temp_file.name
    temp_file.close()

    try:
        await voice_file.download_to_drive(custom_path=temp_path)

        async with aiofiles.open(temp_path, "rb") as audio_stream:
            audio_bytes = await audio_stream.read()

        transcription = await elevenlabs_service.transcribe(audio_bytes, filename="audio.oga")
        text = transcription.get("text", "").strip()

        if not text:
            await update.message.reply_text("❌ Failed to recognize the voice command. Please try again.")
            return

        await update.message.reply_text(f"🗣 Recognized command: {text}")
        await update.message.reply_text("⏳ Processing your request...")

        result = await invoke_agent(
            user_id=user_id,
            raw_input=text,
            message_type='voice',
            extra_state={'transcription': transcription}
        )

        response_text = result.get('response', 'Action completed.')

        if result.get('error'):
            response_text = f"❌ Error: {result['error']}\n\n{response_text}"
        else:
            response_text = f"✅ {response_text}"

        await update.message.reply_text(response_text)
        logger.info("Voice command processed for user %s", user_id)

    except Exception as e:
        logger.error("Error processing voice message: %s", e, exc_info=True)
        await update.message.reply_text(
            f"❌ An error occurred while processing the voice message:\n{str(e)}\n\n"
            "Please try again later or use a text command."
        )
    finally:
        try:
            os.remove(temp_path)
        except FileNotFoundError:
            pass
        except OSError as removal_error:
            logger.warning("Failed to remove temporary file %s: %s", temp_path, removal_error)


async def add_contact_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_id = str(update.effective_user.id)
    args = context.args

    if len(args) < 2:
        await update.message.reply_text("Usage: /addcontact Name 0xAddress")
        return

    name = args[0].strip()
    wallet = args[1].strip()

    if not name or not wallet:
        await update.message.reply_text("Both name and address must be provided.")
        return

    success = await supabase_service.upsert_contact(user_id, name, wallet)

    if success:
        await update.message.reply_text(f"✅ Contact {name} saved.")
    else:
        await update.message.reply_text("❌ Failed to save the contact. Please try again.")


async def list_contacts_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_id = str(update.effective_user.id)

    contacts = await supabase_service.get_contacts(user_id)

    if not contacts:
        await update.message.reply_text("You do not have any saved contacts yet.")
        return

    formatted = "\n".join(f"- {c['name']}: {c['wallet_address']}" for c in contacts)
    await update.message.reply_text(f"📇 Contacts:\n{formatted}")


async def delete_contact_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_id = str(update.effective_user.id)
    args = context.args

    if not args:
        await update.message.reply_text("Usage: /deletecontact Name")
        return

    name = " ".join(args).strip()

    if not name:
        await update.message.reply_text("Specify the contact name.")
        return

    success = await supabase_service.delete_contact(user_id, name)

    if success:
        await update.message.reply_text(f"✅ Contact {name} deleted.")
    else:
        await update.message.reply_text("❌ Contact not found or could not be deleted.")


async def voice_help_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text(
        "🎙 Sample voice commands:\n"
        "- \"Check my wallet balance\"\n"
        "- \"Send Alice 25 USDC for her birthday\"\n"
        "- \"Request test USDC tokens\"\n\n"
        "Tips:\n"
        "• Speak clearly and mention a saved contact by name.\n"
        "• If the contact is missing, add it with /addcontact Name 0xAddress."
    )


async def error_handler(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """
    Global error handler.
    """
    logger.error(f"Error while handling update: {context.error}", exc_info=context.error)
    
    if update and update.effective_message:
        await update.effective_message.reply_text(
            "❌ An unexpected error occurred. Please try again later."
        )


def main():
    """
    Entry point for running the bot.
    """
    if not settings.validate():
        logger.error("Not all required environment variables are set")
        sys.exit(1)
    
    logger.info("Starting the AI Agent bot...")
    
    application = Application.builder().token(settings.TELEGRAM_BOT_TOKEN).build()
    
    application.add_handler(CommandHandler("start", start_command))
    application.add_handler(CommandHandler("help", help_command))
    application.add_handler(CommandHandler("voice_help", voice_help_command))
    application.add_handler(CommandHandler("addcontact", add_contact_command))
    application.add_handler(CommandHandler("listcontacts", list_contacts_command))
    application.add_handler(CommandHandler("deletecontact", delete_contact_command))
    application.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, handle_message))
    application.add_handler(MessageHandler(filters.VOICE, handle_voice_message))
    
    application.add_error_handler(error_handler)
    
    logger.info("Bot started and ready to work!")
    
    application.run_polling(allowed_updates=Update.ALL_TYPES)


if __name__ == '__main__':
    main()

