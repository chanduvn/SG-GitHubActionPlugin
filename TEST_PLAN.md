# One Identity Safeguard GitHub Action — Test Plan

## Overview

This document outlines the testing strategy for the `sg-github-action-plugin` custom GitHub Action. Testing is structured in three tiers: **unit tests**, **integration tests**, and **end-to-end (E2E) pipeline tests**.

---

## 1. Unit Tests (No Network Required)

Unit tests validate the action's logic by mocking `@actions/core` and `@actions/http-client`.

### Setup

```bash
npm install
npm test
```

### What to test

| Test Case | Description |
|-----------|-------------|
| Missing required inputs | Verify `core.setFailed()` is called when `appliance_url`, `api_token`, `asset_name`, or `account_name` are missing |
| Auth failure (HTTP 401) | Mock HTTP client returns 401 → action fails with clear auth error message |
| Auth failure (HTTP 403) | Mock HTTP client returns 403 → action fails with permissions error |
| Account not found | Mock returns valid accounts list but none match the input asset/account → clear "not found" error |
| Empty accounts list | Mock returns `[]` → action fails explaining no registrations exist |
| Successful retrieval | Mock returns matching account + password → `core.setSecret()` and `core.setOutput()` called correctly |
| Password masking | Verify `core.setSecret()` is called with both the API token AND the retrieved password |
| Invalid JSON response | Mock returns malformed JSON → graceful error message |
| SSL toggle | Verify `ignoreSslError` is set correctly based on `ignore_ssl` input |
| Case-insensitive match | Asset/account name matching is case-insensitive |

### Example Test File (`__tests__/index.test.ts`)

```typescript
import * as core from '@actions/core';
import * as http from '@actions/http-client';

// Mock @actions/core
jest.mock('@actions/core');
jest.mock('@actions/http-client');

const mockGetInput = core.getInput as jest.MockedFunction<typeof core.getInput>;
const mockSetFailed = core.setFailed as jest.MockedFunction<typeof core.setFailed>;
const mockSetSecret = core.setSecret as jest.MockedFunction<typeof core.setSecret>;
const mockSetOutput = core.setOutput as jest.MockedFunction<typeof core.setOutput>;

describe('Safeguard A2A Action', () => {
  beforeEach(() => {
    jest.clearAllMocks();
    // Set default inputs
    mockGetInput.mockImplementation((name: string) => {
      const inputs: Record<string, string> = {
        appliance_url: 'https://safeguard.example.com',
        api_token: 'test-api-key-123',
        asset_name: 'prod-db-server',
        account_name: 'svc_deploy',
        ignore_ssl: 'false',
        api_version: '4',
      };
      return inputs[name] || '';
    });
  });

  it('should mask the API token immediately', async () => {
    // ... setup mocks, run action
    expect(mockSetSecret).toHaveBeenCalledWith('test-api-key-123');
  });

  it('should fail with auth error on HTTP 401', async () => {
    // ... mock HTTP response with 401
    expect(mockSetFailed).toHaveBeenCalledWith(
      expect.stringContaining('Authentication failed')
    );
  });

  it('should mask retrieved password before setting output', async () => {
    // ... mock successful retrieval of 'SuperSecret123'
    expect(mockSetSecret).toHaveBeenCalledWith('SuperSecret123');
    expect(mockSetOutput).toHaveBeenCalledWith('password', 'SuperSecret123');
  });
});
```

### How to run

```bash
npm test
# Or with coverage:
npx jest --coverage
```

---

## 2. Integration Tests (Requires Live Safeguard Appliance)

Integration tests exercise real HTTP calls against a Safeguard lab appliance.

### Prerequisites

Set these environment variables pointing to your Safeguard dev/lab instance:

```powershell
$env:SAFEGUARD_APPLIANCE_URL = "https://safeguard-lab.example.com"
$env:SAFEGUARD_A2A_TOKEN = "<your-a2a-api-key>"
$env:SAFEGUARD_ASSET_NAME = "test-server-01"
$env:SAFEGUARD_ACCOUNT_NAME = "test-account"
$env:SAFEGUARD_IGNORE_SSL = "true"
```

### Test Cases

| Test Case | Description | Expected Outcome |
|-----------|-------------|------------------|
| Valid credentials | Correct API key + asset + account | Returns non-empty password string |
| Invalid API key | Garbage token | HTTP 401 with clear error |
| Valid key, wrong asset | API key is valid but asset doesn't match | "No matching account" error listing available accounts |
| Valid key, wrong account | API key is valid but account doesn't match | "No matching account" error |
| Unreachable appliance | Non-existent hostname | Network/timeout error |
| Expired API key | Use a revoked API key | HTTP 401/403 error |

### How to run

Create `__tests__/integration.test.ts`:

```typescript
import * as http from '@actions/http-client';

const APPLIANCE_URL = process.env.SAFEGUARD_APPLIANCE_URL!;
const API_TOKEN = process.env.SAFEGUARD_A2A_TOKEN!;

describe('Safeguard A2A Integration', () => {
  const client = new http.HttpClient('test', undefined, { ignoreSslError: true });

  it('should list retrievable accounts', async () => {
    const url = `${APPLIANCE_URL}/service/a2a/v4/A2ARegistrations/RetrievableAccounts`;
    const response = await client.get(url, {
      Authorization: `A2A ${API_TOKEN}`,
      Accept: 'application/json',
    });
    expect(response.message.statusCode).toBe(200);
    const body = JSON.parse(await response.readBody());
    expect(Array.isArray(body)).toBe(true);
    expect(body.length).toBeGreaterThan(0);
  });

  it('should retrieve a password', async () => {
    // First get the API key for the specific account
    const url = `${APPLIANCE_URL}/service/a2a/v4/Credentials?type=Password`;
    const response = await client.get(url, {
      Authorization: `A2A ${API_TOKEN}`,
      Accept: 'application/json',
    });
    expect(response.message.statusCode).toBe(200);
    const password = await response.readBody();
    expect(password.length).toBeGreaterThan(0);
  });
});
```

Run with:
```bash
npx jest __tests__/integration.test.ts --testTimeout=30000
```

---

## 3. End-to-End Pipeline Tests (Full GitHub Actions Workflow)

### Option A: Local Testing with `act`

[`act`](https://github.com/nektos/act) lets you run GitHub Actions locally:

```bash
# Install act
# Windows: winget install nektos.act
# macOS: brew install act

# Create a .secrets file (NEVER commit this)
echo "SAFEGUARD_APPLIANCE_URL=https://safeguard-lab.example.com" > .secrets
echo "SAFEGUARD_A2A_TOKEN=your-api-key" >> .secrets

# Run the workflow locally
act push --secret-file .secrets -W .github/workflows/deploy.yml
```

### Option B: GitHub Actions (CI Environment)

1. Configure repository secrets:
   - `SAFEGUARD_APPLIANCE_URL` — Lab appliance URL
   - `SAFEGUARD_A2A_TOKEN` — A2A registration API key

2. Create `.github/workflows/test.yml`:

```yaml
name: Test Safeguard Action

on:
  pull_request:
    branches: [main]

jobs:
  unit-tests:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with:
          node-version: '20'
      - run: npm ci
      - run: npm test

  integration-test:
    runs-on: ubuntu-latest
    # Only run if secrets are available (not on forks)
    if: github.event.pull_request.head.repo.full_name == github.repository
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with:
          node-version: '20'
      - run: npm ci
      - run: npm run all

      - name: Test action end-to-end
        id: test-retrieval
        uses: ./
        with:
          appliance_url: ${{ secrets.SAFEGUARD_APPLIANCE_URL }}
          api_token: ${{ secrets.SAFEGUARD_A2A_TOKEN }}
          asset_name: ${{ secrets.TEST_ASSET_NAME }}
          account_name: ${{ secrets.TEST_ACCOUNT_NAME }}
          ignore_ssl: 'true'

      - name: Verify output exists
        run: |
          if [ -z "${{ steps.test-retrieval.outputs.password }}" ]; then
            echo "ERROR: No password retrieved"
            exit 1
          fi
          echo "Password retrieved successfully (masked in logs)"
```

---

## 4. Security Testing

| Test Case | Validation |
|-----------|-----------|
| Password never in logs | Run action with `ACTIONS_STEP_DEBUG=true` — password must appear as `***` |
| API token never in logs | Search all log output — API token must never appear in cleartext |
| No credential in error messages | Force errors and verify no secrets leak in `core.setFailed()` messages |
| TLS enforced by default | Without `ignore_ssl: true`, self-signed certs must cause failure |
| Input validation | Verify empty/malformed URLs don't cause injection or unexpected HTTP calls |

### Log Masking Validation

```bash
# In a workflow, enable debug logging and verify masking:
env:
  ACTIONS_STEP_DEBUG: true

# After the run, search logs:
# - The actual password value should NEVER appear
# - It should always show as ***
```

---

## 5. Running All Tests

```bash
# Install dependencies
npm ci

# Run unit tests with coverage
npm test

# Build and package
npm run all

# Integration tests (requires env vars)
npx jest __tests__/integration.test.ts --testTimeout=30000

# Local E2E with act
act push --secret-file .secrets -W .github/workflows/deploy.yml
```

---

## 6. Safeguard Lab Setup Checklist

Before running integration/E2E tests, ensure:

- [ ] Safeguard appliance is accessible from the test machine/runner
- [ ] An A2A registration exists with credential retrieval enabled
- [ ] The A2A registration is linked to a specific asset account
- [ ] The target account has a password set
- [ ] The A2A API key has not expired
- [ ] Network access (firewall rules) allows HTTPS to the appliance
- [ ] For GitHub-hosted runners: the appliance must be publicly accessible or use a self-hosted runner
