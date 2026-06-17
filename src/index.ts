import * as core from '@actions/core';
import * as https from 'https';
import { HttpClient } from '@actions/http-client';
import type { RequestHandler, RequestInfo, RequestOptions } from '@actions/http-client/lib/interfaces';
import { HttpClientResponse } from '@actions/http-client';

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
    const apiKey = core.getInput('api_key', { required: true });
    const clientCert = core.getInput('client_certificate', { required: true });
    const clientKey = core.getInput('client_certificate_key', { required: true });
    const clientPassphrase = core.getInput('client_certificate_passphrase');
    const ignoreSsl = core.getInput('ignore_ssl').toLowerCase() === 'true';
    const apiVersion = core.getInput('api_version') || '4';

    // Mask secrets immediately so they never appear in logs
    core.setSecret(apiKey);
    core.setSecret(clientKey);
    if (clientPassphrase) {
      core.setSecret(clientPassphrase);
    }

    core.info(`Connecting to Safeguard appliance: ${applianceUrl}`);

    // --- Configure HTTP client with mutual TLS ---
    const handlers: RequestHandler[] = [
      new CertificateRequestHandler(clientCert, clientKey, clientPassphrase),
    ];

    const clientOptions: RequestOptions = {
      ignoreSslError: ignoreSsl,
    };

    const client = new HttpClient('sg-github-action/1.0', handlers, clientOptions);

    // --- Retrieve the password via A2A Credentials endpoint ---
    const credentialUrl = `${applianceUrl}/service/a2a/v${apiVersion}/Credentials?type=Password`;
    core.debug(`GET ${credentialUrl}`);

    const credentialResponse = await client.get(credentialUrl, {
      'Authorization': `A2A ${apiKey}`,
      'Accept': 'application/json',
    });

    const credentialStatus = credentialResponse.message.statusCode ?? 0;
    const credentialBody = await credentialResponse.readBody();

    if (credentialStatus === 401 || credentialStatus === 403) {
      throw new Error(
        `Authentication failed (HTTP ${credentialStatus}). ` +
        'Verify the A2A API key and client certificate are correct.'
      );
    }

    if (credentialStatus === 404) {
      throw new Error(
        `Credential not found (HTTP 404). ` +
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
