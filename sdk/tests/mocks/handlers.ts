/**
 * MSW handlers for mocking SMB Replay API responses.
 */

import { http, HttpResponse } from 'msw';

const BASE_URL = 'http://localhost:3004';

/**
 * Mock API handlers for testing.
 */
export const handlers = [
  // Health
  http.get(`${BASE_URL}/health`, () => {
    return HttpResponse.json({
      status: 'ok',
      version: '1.0.0',
      tshark_available: true,
    });
  }),

  http.get(`${BASE_URL}/info`, () => {
    return HttpResponse.json({
      version: '1.0.0',
      tshark_available: true,
      capture_path: '/test/capture.pcap',
      capture_valid: true,
      supported_commands: { '0': 'Negotiate', '5': 'Create' },
      traces_folder: '/stingray',
      verbosity_level: 0,
      packet_count: 1000,
    });
  }),

  // Config
  http.get(`${BASE_URL}/api/config`, () => {
    return HttpResponse.json({
      traces_folder: '/stingray',
      capture_path: '/test/capture.pcap',
      verbosity_level: 0,
      session_id: '0x1234',
      case_id: '2010101010',
      trace_name: 'capture.pcap',
      server_ip: '192.168.1.100',
      port: 445,
      domain: 'TESTDOMAIN',
      username: 'testuser',
      password_set: true,
      tree_name: 'testshare',
      max_wait: 5.0,
    });
  }),

  http.put(`${BASE_URL}/api/config`, async ({ request }) => {
    const body = await request.json();
    return HttpResponse.json({
      traces_folder: '/stingray',
      capture_path: '/test/capture.pcap',
      verbosity_level: 0,
      session_id: '0x1234',
      case_id: '2010101010',
      trace_name: 'capture.pcap',
      server_ip: (body as Record<string, unknown>).server_ip ?? '192.168.1.100',
      port: (body as Record<string, unknown>).port ?? 445,
      domain: 'TESTDOMAIN',
      username: 'testuser',
      password_set: true,
      tree_name: 'testshare',
      max_wait: 5.0,
    });
  }),

  http.get(`${BASE_URL}/api/config/:key`, ({ params }) => {
    const values: Record<string, string> = {
      server_ip: '192.168.1.100',
      port: '445',
      traces_folder: '/stingray',
    };
    const key = params.key as string;
    if (key in values) {
      return HttpResponse.json({ key, value: values[key] });
    }
    return HttpResponse.json({ error: 'Unknown key' }, { status: 400 });
  }),

  // Traces
  http.get(`${BASE_URL}/api/traces`, () => {
    return HttpResponse.json({
      traces: [
        { path: 'trace1.pcap', name: 'trace1.pcap', case_id: '2010101010' },
        { path: 'trace2.pcapng', name: 'trace2.pcapng', case_id: '2010101010' },
      ],
      case_id: '2010101010',
      total: 2,
    });
  }),

  http.post(`${BASE_URL}/api/traces/ingest`, async ({ request }) => {
    const body = (await request.json()) as { path: string };
    if (body.path.includes('invalid')) {
      return HttpResponse.json({
        success: false,
        sessions: [],
        session_count: 0,
        error: 'Invalid PCAP file',
      });
    }
    return HttpResponse.json({
      success: true,
      sessions: ['smb2_session_0x1234.parquet'],
      session_count: 1,
      total_frames: 500,
      processing_time: 2.5,
    });
  }),

  // Sessions
  http.get(`${BASE_URL}/api/sessions`, () => {
    return HttpResponse.json({
      sessions: [
        { session_id: '0x1234567890abcdef', file_name: 'smb2_session_0x1234567890abcdef.parquet' },
        { session_id: '0xfedcba0987654321', file_name: 'smb2_session_0xfedcba0987654321.parquet' },
      ],
      capture_path: '/test/capture.pcap',
      total: 2,
    });
  }),

  http.get(`${BASE_URL}/api/sessions/:sessionId`, ({ params }) => {
    const sessionId = params.sessionId as string;
    if (sessionId.includes('notfound')) {
      return HttpResponse.json({ error: 'Session not found' }, { status: 404 });
    }
    return HttpResponse.json({
      session_id: sessionId,
      operations: [
        { Frame: '1', Command: 'Create', Path: 'test\\file.txt', Status: 'STATUS_SUCCESS' },
        { Frame: '2', Command: 'Write', Path: 'test\\file.txt', Status: 'STATUS_SUCCESS' },
      ],
      total: 2,
    });
  }),

  http.post(`${BASE_URL}/api/sessions/:sessionId/operations`, async ({ params }) => {
    const sessionId = params.sessionId as string;
    if (sessionId.includes('notfound')) {
      return HttpResponse.json({ error: 'Session not found' }, { status: 404 });
    }
    return HttpResponse.json({
      session_id: sessionId,
      operations: [
        { Frame: '1', Command: 'Create', Path: 'test\\file.txt', Status: 'STATUS_SUCCESS' },
      ],
      total: 1,
      file_filter: 'test\\file.txt',
    });
  }),

  // Replay
  http.post(`${BASE_URL}/api/replay/validate`, async ({ request }) => {
    const body = (await request.json()) as { session_id: string };
    if (body.session_id.includes('notfound')) {
      return HttpResponse.json({ error: 'Session not found' }, { status: 404 });
    }
    return HttpResponse.json({
      ready: true,
      checks: {
        operations: { valid: true, total_operations: 2, supported_operations: 2, issues: [] },
        file_system: { ready: true, missing_directories: [], warnings: [] },
      },
      errors: [],
      warnings: [],
    });
  }),

  http.post(`${BASE_URL}/api/replay/setup`, async ({ request }) => {
    const body = (await request.json()) as { session_id: string; dry_run?: boolean };
    if (body.session_id.includes('notfound')) {
      return HttpResponse.json({ error: 'Session not found' }, { status: 404 });
    }
    return HttpResponse.json({
      success: true,
      directories_created: 3,
      files_created: 5,
      errors: [],
      warnings: [],
      dry_run: body.dry_run ?? false,
    });
  }),

  http.post(`${BASE_URL}/api/replay/execute`, async ({ request }) => {
    const body = (await request.json()) as { session_id: string };
    if (body.session_id.includes('notfound')) {
      return HttpResponse.json({ error: 'Session not found' }, { status: 404 });
    }
    return HttpResponse.json({
      success: true,
      total_operations: 2,
      successful_operations: 2,
      failed_operations: 0,
      errors: [],
    });
  }),
];
