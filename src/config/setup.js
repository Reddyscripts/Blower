const { setupRateLimits } = require('../middleware/rateLimiter');
const { setupMessageTimeout } = require('../middleware/messageTimeout');
const logger = require('../utils/logger');

const setupBot = (bot) => {
    // Setup bot information
    bot.telegram.getMe().then((botInfo) => {
        bot.options.username = botInfo.username;
        logger.info(`Bot initialized: @${botInfo.username}`);
    });

    // Setup commands list
    bot.telegram.setMyCommands([
        { command: 'start', description: 'Start the bot' },
        { command: 'connect', description: 'Connect your wallet' },
        { command: 'deposit', description: 'Make a deposit' },
        { command: 'withdraw', description: 'Request a withdrawal' },
        { command: 'status', description: 'Check pool status' },
        { command: 'history', description: 'View transaction history' },
        { command: 'help', description: 'Show help information' }
    ]);

    // Setup security features
    setupRateLimits(bot);
    setupMessageTimeout(bot);

    // Setup supported chains
    const supportedChains = process.env.SUPPORTED_CHAINS.split(',');
    logger.info(`Supported chains: ${supportedChains.join(', ')}`);
};

module.exports = { setupBot };