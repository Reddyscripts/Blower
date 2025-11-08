// feeManager.js

/**
 * feeManager.js
 *
 * This module manages the 10% deposit fee system for the Blower repository.
 */

const DEPOSIT_FEE_PERCENTAGE = 0.10;

/**
 * Calculate the fee based on the deposit amount.
 * @param {number} depositAmount - The amount deposited.
 * @returns {number} - The calculated fee.
 */
function calculateDepositFee(depositAmount) {
    if (depositAmount <= 0) {
        throw new Error('Deposit amount must be greater than zero.');
    }
    return depositAmount * DEPOSIT_FEE_PERCENTAGE;
}

/**
 * Process a deposit and apply the fee.
 * @param {number} depositAmount - The amount deposited.
 * @returns {number} - The net amount after fee deduction.
 */
function processDeposit(depositAmount) {
    const fee = calculateDepositFee(depositAmount);
    return depositAmount - fee;
}

// Export the functionalities for use in other modules.
module.exports = {
    calculateDepositFee,
    processDeposit
};
