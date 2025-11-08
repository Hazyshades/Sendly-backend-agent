import os
import sys
import logging
import asyncio
from telegram import Update
from telegram.ext import Application, CommandHandler, MessageHandler, filters, ContextTypes
from agent.graph import create_agent_graph
from config.settings import settings

logging.basicConfig(
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    level=logging.INFO
)

logger = logging.getLogger(__name__)


agent_graph = None


async def start_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """
    Handler for the /start command.
    """
    await update.message.reply_text(
        "👋 Hi! I'm an AI Agent for working with Sendly!\n\n"
        "- Check a balance\n"
        "- Send a transaction\n"
        "- Request testnet tokens\n\n"
        "Just describe what you want to do in natural language!\n\n"
        "Example commands:\n"
        "- 'Check my wallet balance'\n"
        "- 'Send 10 USDC to address 0x...'\n"
        "- 'Request testnet USDC tokens'"
    )


async def help_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """
    Handler for the /help command.
    """
    await update.message.reply_text(
        "📖 Bot usage guide\n\n"
        "Available operations:\n\n"
        "1. **Check balance**\n"
        "   'Check the balance', 'How many tokens do I have'\n\n"
        "2. **Send a transaction**\n"
        "   'Send 10 USDC to 0x...'\n\n"
        "3. **Request testnet tokens**\n"
        "   'Request USDC', 'Give me testnet tokens'\n\n"
        "Just describe what you want to do!"
    )


async def handle_message(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """
    Handler for incoming text messages.
    """
    global agent_graph
    
    user_id = str(update.effective_user.id)
    user_message = update.message.text
    
    logger.info(f"Received message from user {user_id}: {user_message}")
    
    await update.message.reply_text("⏳ Processing your command...")
    
    try:
        if agent_graph is None:
            agent_graph = create_agent_graph()
            logger.info("Agent graph initialized")
        
        initial_state = {
            'user_id': user_id,
            'message_type': 'text',
            'raw_input': user_message,
            'blockchain': settings.DEFAULT_BLOCKCHAIN,
            'fee_level': 'MEDIUM',
            'testnet_tokens_requested': False,
            'response': ''
        }
        
        result = await agent_graph.ainvoke(initial_state)
        
        response_text = result.get('response', 'Operation completed.')
        
        if result.get('error'):
            response_text = f"❌ Error: {result['error']}\n\n{response_text}"
        else:
            response_text = f"✅ {response_text}"
        
        await update.message.reply_text(response_text)
        
        logger.info(f"Response sent to user {user_id}")
    
    except Exception as e:
        logger.error(f"Error while processing user message: {e}", exc_info=True)
        await update.message.reply_text(
            f"❌ An error occurred while processing your command:\n{str(e)}\n\n"
            "Try rephrasing your request or use /help"
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
    application.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, handle_message))
    
    application.add_error_handler(error_handler)
    
    logger.info("Bot started and ready to work!")
    
    application.run_polling(allowed_updates=Update.ALL_TYPES)


if __name__ == '__main__':
    main()

