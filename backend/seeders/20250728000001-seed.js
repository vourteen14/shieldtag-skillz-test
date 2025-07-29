'use strict';

const argon2 = require('argon2');
const { v4: uuidv4 } = require('uuid');

/** @type {import('sequelize-cli').Migration} */
module.exports = {
  async up(queryInterface, Sequelize) {
    const hashedPassword = await argon2.hash('AdminPass123!', {
      type: argon2.argon2id,
      memoryCost: 2 ** 16,
      timeCost: 3,
      parallelism: 1,
    });

    await queryInterface.bulkInsert('users', [
      {
        id: uuidv4(),
        email: 'admin@example.com',
        password: hashedPassword,
        isActive: true,
        lastLogin: null,
        loginAttempts: 0,
        lockUntil: null,
        createdAt: new Date(),
        updatedAt: new Date(),
      },
      {
        id: uuidv4(),
        email: 'user@example.com',
        password: hashedPassword,
        isActive: true,
        lastLogin: null,
        loginAttempts: 0,
        lockUntil: null,
        createdAt: new Date(),
        updatedAt: new Date(),
      },
    ]);
  },

  async down(queryInterface, Sequelize) {
    await queryInterface.bulkDelete('users', {
      email: {
        [Sequelize.Op.in]: ['admin@example.com', 'user@example.com']
      }
    });
  }
};