/**
 * Vitest Setup File
 * Configures test environment and global utilities
 */

import { beforeAll, afterAll, beforeEach, afterEach } from 'vitest';
import { join } from 'path';
import { mkdir, rm } from 'fs/promises';
import os from 'os';

// Test environment configuration
const TEST_JAIL_ROOT = join(os.tmpdir(), 'redquanta-test', String(Date.now()));

// Global test configuration
beforeAll(async () => {
  // Set test environment variables
  process.env.NODE_ENV = 'test';
  process.env.LOG_LEVEL = 'error'; // Reduce log noise during tests
  process.env.JAIL_ROOT = TEST_JAIL_ROOT;
  process.env.DANGEROUS_MODE = 'false'; // Start with safe mode
  process.env.CACHE_ENABLED = 'false'; // Disable cache for predictable tests
  process.env.WEB_SEARCH_ENABLED = 'false'; // Disable external dependencies
  
  // Create test jail directory
  await mkdir(TEST_JAIL_ROOT, { recursive: true });
  
  console.log(`🧪 Test environment initialized at: ${TEST_JAIL_ROOT}`);
});

afterAll(async () => {
  // Clean up test jail directory
  try {
    await rm(TEST_JAIL_ROOT, { recursive: true, force: true });
    console.log('🧹 Test environment cleaned up');
  } catch (error) {
    console.warn('Warning: Could not clean up test directory:', error);
  }
});

beforeEach(() => {
  // Reset environment for each test
  process.env.DANGEROUS_MODE = 'false';
  process.env.MCP_MODE = 'stdio';
});

afterEach(() => {
  // Cleanup after each test if needed
});

// Global test utilities
declare global {
  var TEST_JAIL_ROOT: string;
  var createTestFile: (filename: string, content: string) => Promise<string>;
  var enableDangerousMode: () => void;
  var disableDangerousMode: () => void;
}

// Make test utilities globally available
global.TEST_JAIL_ROOT = TEST_JAIL_ROOT;

global.createTestFile = async (filename: string, content: string): Promise<string> => {
  const { writeFile } = await import('fs/promises');
  const { join } = await import('path');
  
  const filePath = join(TEST_JAIL_ROOT, filename);
  await writeFile(filePath, content, 'utf8');
  return filePath;
};

global.enableDangerousMode = () => {
  process.env.DANGEROUS_MODE = 'true';
};

global.disableDangerousMode = () => {
  process.env.DANGEROUS_MODE = 'false';
};

export {
  TEST_JAIL_ROOT,
}; 