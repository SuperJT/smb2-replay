/**
 * Tests for SMBReplayClient.
 */

import { afterAll, afterEach, beforeAll, describe, expect, it } from 'vitest';
import { setupServer } from 'msw/node';
import { SMBReplayClient, NotFoundError, APIError } from '../src';
import { handlers } from './mocks/handlers';

// Setup MSW server
const server = setupServer(...handlers);

beforeAll(() => server.listen({ onUnhandledRequest: 'error' }));
afterEach(() => server.resetHandlers());
afterAll(() => server.close());

describe('SMBReplayClient', () => {
  const client = new SMBReplayClient({
    baseUrl: 'http://localhost:3004',
  });

  describe('Health & Info', () => {
    it('should return health status', async () => {
      const health = await client.healthCheck();
      expect(health.status).toBe('ok');
      expect(health.version).toBe('1.0.0');
      expect(health.tshark_available).toBe(true);
    });

    it('should return system info', async () => {
      const info = await client.getSystemInfo();
      expect(info.version).toBe('1.0.0');
      expect(info.tshark_available).toBe(true);
      expect(info.traces_folder).toBe('/stingray');
    });
  });

  describe('Configuration', () => {
    it('should get config', async () => {
      const config = await client.getConfig();
      expect(config.server_ip).toBe('192.168.1.100');
      expect(config.port).toBe(445);
      expect(config.password_set).toBe(true);
    });

    it('should update config', async () => {
      const config = await client.updateConfig({ server_ip: '10.0.0.1' });
      expect(config.server_ip).toBe('10.0.0.1');
    });

    it('should get config value', async () => {
      const value = await client.getConfigValue('server_ip');
      expect(value.key).toBe('server_ip');
      expect(value.value).toBe('192.168.1.100');
    });

    it('should throw error for invalid config key', async () => {
      await expect(client.getConfigValue('invalid_key')).rejects.toThrow(APIError);
    });
  });

  describe('Traces', () => {
    it('should list traces', async () => {
      const result = await client.listTraces();
      expect(result.traces).toHaveLength(2);
      expect(result.total).toBe(2);
    });

    it('should ingest trace successfully', async () => {
      const result = await client.ingestTrace('/test/valid.pcap');
      expect(result.success).toBe(true);
      expect(result.session_count).toBe(1);
    });

    it('should return failure for invalid trace', async () => {
      const result = await client.ingestTrace('/test/invalid.pcap');
      expect(result.success).toBe(false);
      expect(result.error).toBeDefined();
    });
  });

  describe('Sessions', () => {
    it('should list sessions', async () => {
      const result = await client.listSessions();
      expect(result.sessions).toHaveLength(2);
      expect(result.total).toBe(2);
    });

    it('should get session operations', async () => {
      const result = await client.getOperations('0x1234567890abcdef');
      expect(result.operations).toHaveLength(2);
      expect(result.total).toBe(2);
    });

    it('should get filtered operations with POST', async () => {
      const result = await client.getOperations('0x1234567890abcdef', {
        file_filter: 'test\\file.txt',
      });
      expect(result.file_filter).toBe('test\\file.txt');
    });

    it('should throw NotFoundError for missing session', async () => {
      await expect(client.getOperations('notfound')).rejects.toThrow(NotFoundError);
    });
  });

  describe('Replay', () => {
    it('should validate replay', async () => {
      const result = await client.validateReplay('0x1234567890abcdef');
      expect(result.ready).toBe(true);
      expect(result.checks.operations?.valid).toBe(true);
    });

    it('should throw NotFoundError for missing session validation', async () => {
      await expect(client.validateReplay('notfound')).rejects.toThrow(NotFoundError);
    });

    it('should setup infrastructure', async () => {
      const result = await client.setupInfrastructure('0x1234567890abcdef');
      expect(result.success).toBe(true);
      expect(result.directories_created).toBe(3);
    });

    it('should setup infrastructure with dry run', async () => {
      const result = await client.setupInfrastructure('0x1234567890abcdef', {
        dry_run: true,
      });
      expect(result.dry_run).toBe(true);
    });

    it('should execute replay', async () => {
      const result = await client.executeReplay('0x1234567890abcdef');
      expect(result.success).toBe(true);
      expect(result.total_operations).toBe(2);
      expect(result.successful_operations).toBe(2);
    });

    it('should throw NotFoundError for missing session replay', async () => {
      await expect(client.executeReplay('notfound')).rejects.toThrow(NotFoundError);
    });
  });
});
