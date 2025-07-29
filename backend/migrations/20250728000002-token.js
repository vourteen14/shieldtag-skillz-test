'use strict';

/** @type {import('sequelize-cli').Migration} */
module.exports = {
  async up(queryInterface, Sequelize) {
    await queryInterface.createTable('refresh_tokens', {
      id: {
        type: Sequelize.UUID,
        defaultValue: Sequelize.UUIDV4,
        primaryKey: true,
        allowNull: false,
      },
      token: {
        type: Sequelize.TEXT,
        allowNull: false,
        unique: true,
      },
      userId: {
        type: Sequelize.UUID,
        allowNull: false,
        references: {
          model: 'users',
          key: 'id',
        },
        onUpdate: 'CASCADE',
        onDelete: 'CASCADE',
      },
      expiresAt: {
        type: Sequelize.DATE,
        allowNull: false,
      },
      isActive: {
        type: Sequelize.BOOLEAN,
        defaultValue: true,
        allowNull: false,
      },
      userAgent: {
        type: Sequelize.STRING,
        allowNull: true,
      },
      ipAddress: {
        type: Sequelize.STRING,
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
    await queryInterface.addIndex('refresh_tokens', ['token'], {
      unique: true,
      name: 'refresh_tokens_token_unique_idx',
    });

    await queryInterface.addIndex('refresh_tokens', ['userId'], {
      name: 'refresh_tokens_user_id_idx',
    });

    await queryInterface.addIndex('refresh_tokens', ['expiresAt'], {
      name: 'refresh_tokens_expires_at_idx',
    });

    await queryInterface.addIndex('refresh_tokens', ['isActive'], {
      name: 'refresh_tokens_is_active_idx',
    });

    await queryInterface.addIndex('refresh_tokens', ['userId', 'isActive'], {
      name: 'refresh_tokens_user_active_idx',
    });
  },

  async down(queryInterface, Sequelize) {
    await queryInterface.dropTable('refresh_tokens');
  }
};