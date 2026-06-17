import * as core from '@actions/core';
import * as https from 'https';
import { HttpClient } from '@actions/http-client';
import type { RequestHandler, RequestInfo, RequestOptions } from '@actions/http-client/lib/interfaces';
import { HttpClientResponse } from '@actions/http-client';

interface RetrievableAccount {
  AccountId: number;
  AccountName: string;
  AssetId: number;
  AssetName: string;
  DomainName: string | null;
  ApiKey: string;
}

/**
 * RequestHandler that injects a client certificate into every outgoing HTTPS request.
 * Safeguard A2A requires mutual TLS — the appliance validates the client certificate
 * before accepting any A2A API call.
 */
class CertificateRequestHandler implements RequestHandler {
  private cert: string;
  private key: string;
  private passphrase: string | undefined;

  constructor(cert: string, key: string, passphrase?: string) {
    this.cert = cert;
    this.key = key;
    this.passphrase = passphrase || undefined;
  }

  prepareRequest(options: https.RequestOptions): void {
    options.cert = this.cert;
    options.key = this.key;
    if (this.passphrase) {
      options.passphrase = this.passphrase;
    }
  }

  canHandleAuthentication(): boolean {
    return false;
  }

  async handleAuthentication(): Promise<HttpClientResponse> {
    throw new Error('Certificate handler does not handle HTTP-level authentication');
  }
}

async function run(): Promise<void> {
  try {
    // --- Read inputs ---
    const applianceUrl = core.getInput('appliance_url', { required: true }).replace(/\/+$/, '');
    const apiToken = core.getInput('api_token', { required: true });
    const clientCert = core.getInput('client_certificate', { required: true });
    const clientKey = core.getInput('client_certificate_key', { required: true });
    const clientPassphrase = core.getInput('client_certificate_passphrase');
    const assetName = core.getInput('asset_name', { required: true });
    const accountName = core.getInput('account_name', { required: true });
    const ignoreSsl = core.getInput('ignore_ssl').toLowerCase() === 'true';
    const apiVersion = core.getInput('api_version') || '4';

    // Mask secrets immediately so they never appear in logs
    core.setSecret(apiToken);
    core.setSecret(clientKey);
    if (clientPassphrase) {
      core.setSecret(clientPassphrase);
    }

    core.info(`Connecting to Safeguard appliance: ${applianceUrl}`);
    core.info(`Retrieving credential for asset="${assetName}" account="${accountName}"`);

    // --- Configure HTTP client with mutual TLS ---
    const handlers: RequestHandler[] = [
      new CertificateRequestHandler(clientCert, clientKey, clientPassphrase),
    ];

    const clientOptions: RequestOptions = {
      ignoreSslError: ignoreSsl,
    };

    const client = new HttpClient('sg-github-action/1.0', handlers, clientOptions);

    // --- Step 1: Discover retrievable accounts to find the matching API key ---
    const retrievableUrl = `${applianceUrl}/service/a2a/v${apiVersion}/A2ARegistrations/RetrievableAccounts`;
    core.debug(`GET ${retrievableUrl}`);

    const retrievableResponse = await client.get(retrievableUrl, {
      'Authorization': `A2A ${apiToken}`,
      'Accept': 'application/json',
    });

    const retrievableStatus = retrievableResponse.message.statusCode ?? 0;
    const retrievableBody = await retrievableResponse.readBody();

    if (retrievableStatus === 401 || retrievableStatus === 403) {
      throw new Error(
        `Authentication failed (HTTP ${retrievableStatus}). ` +
        'Verify the A2A API token is correct and has not expired.'
      );
    }

    if (retrievableStatus < 200 || retrievableStatus >= 300) {
      throw new Error(
        `Failed to list retrievable accounts (HTTP ${retrievableStatus}): ${retrievableBody}`
      );
    }

    let accounts: RetrievableAccount[];
    try {
      accounts = JSON.parse(retrievableBody);
    } catch {
      throw new Error(`Invalid JSON response from retrievable accounts endpoint: ${retrievableBody}`);
    }

    if (!Array.isArray(accounts) || accounts.length === 0) {
      throw new Error(
        'No retrievable accounts found for this A2A registration. ' +
        'Ensure the A2A registration is configured with credential retrieval access.'
      );
    }

    // --- Step 2: Find the matching account ---
    const matchedAccount = accounts.find(
      (a) =>
        a.AssetName.toLowerCase() === assetName.toLowerCase() &&
        a.AccountName.toLowerCase() === accountName.toLowerCase()
    );

    if (!matchedAccount) {
      const available = accounts
        .map((a) => `${a.AssetName}/${a.AccountName}`)
        .join(', ');
      throw new Error(
        `No matching account found for asset="${assetName}" account="${accountName}". ` +
        `Available accounts: [${available}]`
      );
    }

    core.info(`Found matching account (AccountId=${matchedAccount.AccountId}) on asset "${matchedAccount.AssetName}"`);

    // --- Step 3: Retrieve the password ---
    const credentialUrl = `${applianceUrl}/service/a2a/v${apiVersion}/Credentials?type=Password`;
    core.debug(`GET ${credentialUrl}`);

    const credentialResponse = await client.get(credentialUrl, {
      'Authorization': `A2A ${matchedAccount.ApiKey}`,
      'Accept': 'application/json',
    });

    const credentialStatus = credentialResponse.message.statusCode ?? 0;
    const credentialBody = await credentialResponse.readBody();

    if (credentialStatus === 401 || credentialStatus === 403) {
      throw new Error(
        `Credential retrieval authentication failed (HTTP ${credentialStatus}). ` +
        'The A2A API key for this account may be invalid or revoked.'
      );
    }

    if (credentialStatus === 404) {
      throw new Error(
        `Credential not found (HTTP 404) for asset="${assetName}" account="${accountName}". ` +
        'The password may not be set or the account may have been removed.'
      );
    }

    if (credentialStatus < 200 || credentialStatus >= 300) {
      throw new Error(
        `Failed to retrieve credential (HTTP ${credentialStatus}): ${credentialBody}`
      );
    }

    // The A2A Credentials endpoint returns the password as a bare string (JSON-encoded)
    let password: string;
    try {
      password = JSON.parse(credentialBody);
    } catch {
      // Some Safeguard versions return the password as plain text without JSON wrapping
      password = credentialBody.trim();
    }

    if (!password) {
      throw new Error('Retrieved an empty password. Verify the account has a password set in Safeguard.');
    }

    // --- CRITICAL: Mask the password in all subsequent log output ---
    core.setSecret(password);

    // --- Set the output ---
    core.setOutput('password', password);
    core.info('Successfully retrieved and masked the credential.');
  } catch (error) {
    if (error instanceof Error) {
      core.setFailed(error.message);
    } else {
      core.setFailed('An unexpected error occurred while retrieving the credential.');
    }
  }
}

run();
