'use strict';

/** @type {import('sequelize-cli').Migration} */
module.exports = {
  async up(queryInterface, Sequelize) {
    await queryInterface.createTable('users', {
      id: {
        type: Sequelize.UUID,
        defaultValue: Sequelize.UUIDV4,
        primaryKey: true,
        allowNull: false,
      },
      email: {
        type: Sequelize.STRING,
        allowNull: false,
        unique: true,
        validate: {
          isEmail: true,
          len: [5, 255],
        },
      },
      fullName: {
        type: Sequelize.STRING,
        allowNull: false,
        validate: {
          len: [2, 100],
          notEmpty: true,
        },
      },
      password: {
        type: Sequelize.STRING,
        allowNull: false,
        validate: {
          len: [6, 255],
        },
      },
      isActive: {
        type: Sequelize.BOOLEAN,
        defaultValue: true,
        allowNull: false,
      },
      lastLogin: {
        type: Sequelize.DATE,
        allowNull: true,
      },
      loginAttempts: {
        type: Sequelize.INTEGER,
        defaultValue: 0,
        allowNull: false,
      },
      lockUntil: {
        type: Sequelize.DATE,
        allowNull: true,
      },
      createdAt: {
        type: Sequelize.DATE,
        allowNull: false,
        defaultValue: Sequelize.literal('CURRENT_TIMESTAMP'),
      },
      updatedAt: {
        type: Sequelize.DATE,
        allowNull: false,
        defaultValue: Sequelize.literal('CURRENT_TIMESTAMP'),
      },
    });

    // Add indexes for performance
    await queryInterface.addIndex('users', ['email'], {
      unique: true,
      name: 'users_email_unique_idx',
    });

    await queryInterface.addIndex('users', ['isActive'], {
      name: 'users_is_active_idx',
    });

    await queryInterface.addIndex('users', ['lockUntil'], {
      name: 'users_lock_until_idx',
    });
  },

  async down(queryInterface, Sequelize) {
    await queryInterface.dropTable('users');
  }
};