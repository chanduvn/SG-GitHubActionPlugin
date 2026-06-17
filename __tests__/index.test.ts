import * as core from '@actions/core';
import { HttpClient } from '@actions/http-client';

jest.mock('@actions/core');
jest.mock('@actions/http-client');

const mockedCore = jest.mocked(core);
const MockedHttpClient = jest.mocked(HttpClient);

function setupInputs(overrides: Record<string, string> = {}): void {
  const defaults: Record<string, string> = {
    appliance_url: 'https://safeguard.example.com',
    api_token: 'test-a2a-api-key-abc123',
    client_certificate: '-----BEGIN CERTIFICATE-----\nMIItest\n-----END CERTIFICATE-----',
    client_certificate_key: '-----BEGIN PRIVATE KEY-----\nMIItest\n-----END PRIVATE KEY-----',
    client_certificate_passphrase: '',
    asset_name: 'prod-db-server',
    account_name: 'svc_deploy',
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

  it('should mask the API token immediately on startup', async () => {
    setupInputs();
    mockGet.mockResolvedValueOnce(mockHttpResponse(401, 'Unauthorized'));

    await jest.isolateModulesAsync(async () => {
      await import('../src/index');
    });

    expect(mockedCore.setSecret).toHaveBeenCalledWith('test-a2a-api-key-abc123');
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

    // HttpClient should be constructed with a handlers array containing the cert handler
    expect(MockedHttpClient).toHaveBeenCalledWith(
      'sg-github-action/1.0',
      expect.arrayContaining([expect.objectContaining({ cert: expect.any(String) })]),
      expect.any(Object)
    );
  });

  it('should fail with auth error on HTTP 401 from retrievable accounts', async () => {
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

  it('should fail when no accounts are returned', async () => {
    setupInputs();
    mockGet.mockResolvedValueOnce(mockHttpResponse(200, '[]'));

    await jest.isolateModulesAsync(async () => {
      await import('../src/index');
    });

    expect(mockedCore.setFailed).toHaveBeenCalledWith(
      expect.stringContaining('No retrievable accounts found')
    );
  });

  it('should fail when asset/account name does not match', async () => {
    setupInputs();
    const accounts = [
      { AccountId: 1, AccountName: 'other_account', AssetId: 10, AssetName: 'other-server', DomainName: null, ApiKey: 'key-1' },
    ];
    mockGet.mockResolvedValueOnce(mockHttpResponse(200, JSON.stringify(accounts)));

    await jest.isolateModulesAsync(async () => {
      await import('../src/index');
    });

    expect(mockedCore.setFailed).toHaveBeenCalledWith(
      expect.stringContaining('No matching account found')
    );
  });

  it('should retrieve password and mask it before setting output', async () => {
    setupInputs();
    const accounts = [
      { AccountId: 42, AccountName: 'svc_deploy', AssetId: 10, AssetName: 'prod-db-server', DomainName: null, ApiKey: 'account-specific-key' },
    ];
    mockGet
      .mockResolvedValueOnce(mockHttpResponse(200, JSON.stringify(accounts)))
      .mockResolvedValueOnce(mockHttpResponse(200, JSON.stringify('SuperSecret!123')));

    await jest.isolateModulesAsync(async () => {
      await import('../src/index');
    });

    // Password must be masked
    expect(mockedCore.setSecret).toHaveBeenCalledWith('SuperSecret!123');
    // Password must be set as output
    expect(mockedCore.setOutput).toHaveBeenCalledWith('password', 'SuperSecret!123');
    // Action should not fail
    expect(mockedCore.setFailed).not.toHaveBeenCalled();
  });

  it('should match asset/account names case-insensitively', async () => {
    setupInputs({ asset_name: 'PROD-DB-SERVER', account_name: 'SVC_DEPLOY' });
    const accounts = [
      { AccountId: 42, AccountName: 'svc_deploy', AssetId: 10, AssetName: 'prod-db-server', DomainName: null, ApiKey: 'key-1' },
    ];
    mockGet
      .mockResolvedValueOnce(mockHttpResponse(200, JSON.stringify(accounts)))
      .mockResolvedValueOnce(mockHttpResponse(200, JSON.stringify('MyPassword')));

    await jest.isolateModulesAsync(async () => {
      await import('../src/index');
    });

    expect(mockedCore.setOutput).toHaveBeenCalledWith('password', 'MyPassword');
  });

  it('should handle credential retrieval HTTP 404', async () => {
    setupInputs();
    const accounts = [
      { AccountId: 42, AccountName: 'svc_deploy', AssetId: 10, AssetName: 'prod-db-server', DomainName: null, ApiKey: 'key-1' },
    ];
    mockGet
      .mockResolvedValueOnce(mockHttpResponse(200, JSON.stringify(accounts)))
      .mockResolvedValueOnce(mockHttpResponse(404, 'Not Found'));

    await jest.isolateModulesAsync(async () => {
      await import('../src/index');
    });

    expect(mockedCore.setFailed).toHaveBeenCalledWith(
      expect.stringContaining('Credential not found')
    );
  });

  it('should fail when retrieved password is empty', async () => {
    setupInputs();
    const accounts = [
      { AccountId: 42, AccountName: 'svc_deploy', AssetId: 10, AssetName: 'prod-db-server', DomainName: null, ApiKey: 'key-1' },
    ];
    mockGet
      .mockResolvedValueOnce(mockHttpResponse(200, JSON.stringify(accounts)))
      .mockResolvedValueOnce(mockHttpResponse(200, '""'));

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
