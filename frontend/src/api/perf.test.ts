import { beforeEach, describe, expect, it, vi } from 'vitest';

import { listPerf, listPerfSummary } from './perf';
import { apiFetch, getApiBase } from './client';

vi.mock('./client', () => ({
  apiFetch: vi.fn().mockResolvedValue([]),
  getApiBase: vi.fn(),
}));

const mockedApiFetch = vi.mocked(apiFetch);
const mockedGetApiBase = vi.mocked(getApiBase);

describe('perf api', () => {
  beforeEach(() => {
    mockedApiFetch.mockClear();
    mockedGetApiBase.mockClear();
  });

  it('adds python source when api base is /api', async () => {
    mockedGetApiBase.mockReturnValue('/api');
    await listPerf('token');
    const path = mockedApiFetch.mock.calls[0][0] as string;
    expect(path).toContain('/perf/');
    expect(path).toContain('source=python');
  });

  it('adds go source when api base is /api-go', async () => {
    mockedGetApiBase.mockReturnValue('/api-go');
    await listPerfSummary('token');
    const path = mockedApiFetch.mock.calls[0][0] as string;
    expect(path).toContain('/perf/summary');
    expect(path).toContain('source=go');
  });

  it('respects explicit source override', async () => {
    mockedGetApiBase.mockReturnValue('/api');
    await listPerf('token', { source: 'custom' });
    const path = mockedApiFetch.mock.calls[0][0] as string;
    expect(path).toContain('source=custom');
  });
});
