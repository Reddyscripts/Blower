require('dotenv').config();
const { Telegraf } = require('telegraf');
const { setupBot } = require('./config/setup');
const { setupCommands } = require('./commands');
const { setupMiddleware } = require('./middleware');
const logger = require('./utils/logger');

const bot = new Telegraf(process.env.BOT_TOKEN);

// Setup bot configuration
setupBot(bot);

// Setup middleware
setupMiddleware(bot);

// Setup commands
setupCommands(bot);

// Error handling
bot.catch((err, ctx) => {
    logger.error('Bot error:', err);
    ctx.reply('An error occurred while processing your request.');
});

// Start bot
bot.launch()
    .then(() => logger.info('Bot started successfully'))
    .catch(err => logger.error('Failed to start bot:', err));

// Enable graceful stop
process.once('SIGINT', () => bot.stop('SIGINT'));
process.once('SIGTERM', () => bot.stop('SIGTERM'));