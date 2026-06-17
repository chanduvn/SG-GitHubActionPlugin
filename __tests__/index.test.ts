import * as core from '@actions/core';
import { HttpClient } from '@actions/http-client';

jest.mock('@actions/core');
jest.mock('@actions/http-client');

const mockedCore = jest.mocked(core);
const MockedHttpClient = jest.mocked(HttpClient);

function setupInputs(overrides: Record<string, string> = {}): void {
  const defaults: Record<string, string> = {
    appliance_url: 'https://safeguard.example.com',
    api_key: 'Q5jyDdUcLG0qFNGFumh43SiAcZRV2Ash7wcX4M9P1ro=',
    client_certificate: '-----BEGIN CERTIFICATE-----\nMIItest\n-----END CERTIFICATE-----',
    client_certificate_key: '-----BEGIN PRIVATE KEY-----\nMIItest\n-----END PRIVATE KEY-----',
    client_certificate_passphrase: '',
    ignore_ssl: 'false',
    api_version: '4',
  };
  const inputs = { ...defaults, ...overrides };

  mockedCore.getInput.mockImplementation((name: string) => inputs[name] || '');
}

function mockHttpResponse(statusCode: number, body: string) {
  return {
    message: { statusCode },
    readBody: jest.fn().mockResolvedValue(body),
  };
}

describe('Safeguard A2A GitHub Action', () => {
  let mockGet: jest.Mock;

  beforeEach(() => {
    jest.clearAllMocks();
    mockGet = jest.fn();
    MockedHttpClient.mockImplementation(() => ({ get: mockGet } as unknown as HttpClient));
  });

  it('should mask the API key immediately on startup', async () => {
    setupInputs();
    mockGet.mockResolvedValueOnce(mockHttpResponse(401, 'Unauthorized'));

    await jest.isolateModulesAsync(async () => {
      await import('../src/index');
    });

    expect(mockedCore.setSecret).toHaveBeenCalledWith('Q5jyDdUcLG0qFNGFumh43SiAcZRV2Ash7wcX4M9P1ro=');
  });

  it('should mask the client certificate key on startup', async () => {
    setupInputs();
    mockGet.mockResolvedValueOnce(mockHttpResponse(401, 'Unauthorized'));

    await jest.isolateModulesAsync(async () => {
      await import('../src/index');
    });

    expect(mockedCore.setSecret).toHaveBeenCalledWith(
      '-----BEGIN PRIVATE KEY-----\nMIItest\n-----END PRIVATE KEY-----'
    );
  });

  it('should pass certificate handler to HttpClient', async () => {
    setupInputs();
    mockGet.mockResolvedValueOnce(mockHttpResponse(401, 'Unauthorized'));

    await jest.isolateModulesAsync(async () => {
      await import('../src/index');
    });

    expect(MockedHttpClient).toHaveBeenCalledWith(
      'sg-github-action/1.0',
      expect.arrayContaining([expect.objectContaining({ cert: expect.any(String) })]),
      expect.any(Object)
    );
  });

  it('should fail with auth error on HTTP 401', async () => {
    setupInputs();
    mockGet.mockResolvedValueOnce(mockHttpResponse(401, 'Unauthorized'));

    await jest.isolateModulesAsync(async () => {
      await import('../src/index');
    });

    expect(mockedCore.setFailed).toHaveBeenCalledWith(
      expect.stringContaining('Authentication failed')
    );
  });

  it('should fail with auth error on HTTP 403', async () => {
    setupInputs();
    mockGet.mockResolvedValueOnce(mockHttpResponse(403, 'Forbidden'));

    await jest.isolateModulesAsync(async () => {
      await import('../src/index');
    });

    expect(mockedCore.setFailed).toHaveBeenCalledWith(
      expect.stringContaining('Authentication failed')
    );
  });

  it('should retrieve password and mask it before setting output', async () => {
    setupInputs();
    mockGet.mockResolvedValueOnce(mockHttpResponse(200, JSON.stringify('SuperSecret!123')));

    await jest.isolateModulesAsync(async () => {
      await import('../src/index');
    });

    expect(mockedCore.setSecret).toHaveBeenCalledWith('SuperSecret!123');
    expect(mockedCore.setOutput).toHaveBeenCalledWith('password', 'SuperSecret!123');
    expect(mockedCore.setFailed).not.toHaveBeenCalled();
  });

  it('should handle credential retrieval HTTP 404', async () => {
    setupInputs();
    mockGet.mockResolvedValueOnce(mockHttpResponse(404, 'Not Found'));

    await jest.isolateModulesAsync(async () => {
      await import('../src/index');
    });

    expect(mockedCore.setFailed).toHaveBeenCalledWith(
      expect.stringContaining('Credential not found')
    );
  });

  it('should fail when retrieved password is empty', async () => {
    setupInputs();
    mockGet.mockResolvedValueOnce(mockHttpResponse(200, '""'));

    await jest.isolateModulesAsync(async () => {
      await import('../src/index');
    });

    expect(mockedCore.setFailed).toHaveBeenCalledWith(
      expect.stringContaining('empty password')
    );
  });

  it('should pass ignoreSslError when ignore_ssl is true', async () => {
    setupInputs({ ignore_ssl: 'true' });
    mockGet.mockResolvedValueOnce(mockHttpResponse(401, 'Unauthorized'));

    await jest.isolateModulesAsync(async () => {
      await import('../src/index');
    });

    expect(MockedHttpClient).toHaveBeenCalledWith(
      'sg-github-action/1.0',
      expect.any(Array),
      expect.objectContaining({ ignoreSslError: true })
    );
  });
});
