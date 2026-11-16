import * as core from '@actions/core';
import * as https from 'https';
import { HttpClient } from '@actions/http-client';
import type { RequestHandler, RequestOptions } from '@actions/http-client/lib/interfaces';
import { HttpClientResponse } from '@actions/http-client';

/**
 * RequestHandler that sets the TLS options of every outgoing HTTPS request.
 * Safeguard A2A requires mutual TLS: the appliance validates the client
 * certificate before accepting any A2A API call.
 */
class CertificateRequestHandler implements RequestHandler {
  constructor(
    private cert: string,
    private key: string,
    private passphrase?: string,
    private ca?: string,
  ) {}

  prepareRequest(options: https.RequestOptions): void {
    options.cert = this.cert;
    options.key = this.key;
    if (this.passphrase) {
      options.passphrase = this.passphrase;
    }
    if (this.ca) {
      options.ca = this.ca;
    }
    // The appliance asks for the client certificate after the handshake, which
    // a TLS 1.3 client does not answer; the certificate then never arrives and
    // A2A answers 401. TLS 1.2 works (verified on SPP 9.0).
    options.maxVersion = 'TLSv1.2';
  }

  canHandleAuthentication(): boolean {
    return false;
  }

  async handleAuthentication(): Promise<HttpClientResponse> {
    throw new Error('Certificate handler does not handle HTTP-level authentication');
  }
}

/** A2A `type` query value and the action output that carries the result. */
const CREDENTIAL_TYPES: Record<string, { query: string; output: string }> = {
  password: { query: 'Password', output: 'password' },
  ssh_key: { query: 'PrivateKey', output: 'private_key' },
};

const SSH_KEY_FORMATS = ['OpenSsh', 'Ssh2', 'Putty'];

/** GitHub masks secrets line by line, so register every line of a multi-line value. */
function maskSecret(value: string): void {
  core.setSecret(value);
  for (const line of value.split(/\r?\n/)) {
    if (line.trim().length > 0) {
      core.setSecret(line);
    }
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
    const caCertificate = core.getInput('ca_certificate');
    const ignoreSsl = core.getInput('ignore_ssl').toLowerCase() === 'true';
    const apiVersion = core.getInput('api_version') || '4';
    const credentialType = (core.getInput('credential_type') || 'password').toLowerCase();
    const sshKeyFormat = core.getInput('ssh_key_format') || 'OpenSsh';

    // Mask secrets immediately so they never appear in logs
    core.setSecret(apiKey);
    maskSecret(clientKey);
    if (clientPassphrase) {
      core.setSecret(clientPassphrase);
    }

    const type = CREDENTIAL_TYPES[credentialType];
    if (!type) {
      throw new Error(
        `Unsupported credential_type '${credentialType}'. Use one of: ${Object.keys(CREDENTIAL_TYPES).join(', ')}.`
      );
    }
    if (!SSH_KEY_FORMATS.includes(sshKeyFormat)) {
      throw new Error(`Unsupported ssh_key_format '${sshKeyFormat}'. Use one of: ${SSH_KEY_FORMATS.join(', ')}.`);
    }
    if (ignoreSsl) {
      core.warning('TLS certificate verification is disabled (ignore_ssl). Use ca_certificate instead outside a lab.');
    }

    core.info(`Connecting to Safeguard appliance: ${applianceUrl}`);

    // --- Configure HTTP client with mutual TLS ---
    const handlers: RequestHandler[] = [
      new CertificateRequestHandler(clientCert, clientKey, clientPassphrase || undefined, caCertificate || undefined),
    ];

    const clientOptions: RequestOptions = {
      ignoreSslError: ignoreSsl,
    };

    const client = new HttpClient('sg-github-action/1.1', handlers, clientOptions);

    // --- Retrieve the credential via the A2A Credentials endpoint ---
    let credentialUrl = `${applianceUrl}/service/a2a/v${apiVersion}/Credentials?type=${type.query}`;
    if (credentialType === 'ssh_key') {
      credentialUrl += `&keyFormat=${sshKeyFormat}`;
    }
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
        'The credential may not be set or the account may have been removed.'
      );
    }

    if (credentialStatus < 200 || credentialStatus >= 300) {
      throw new Error(
        `Failed to retrieve credential (HTTP ${credentialStatus}): ${credentialBody}`
      );
    }

    // The A2A Credentials endpoint returns the secret as a bare string (JSON-encoded)
    let secret: string;
    try {
      secret = JSON.parse(credentialBody);
    } catch {
      // Some Safeguard versions return the secret as plain text without JSON wrapping
      secret = credentialBody.trim();
    }

    if (!secret || typeof secret !== 'string') {
      throw new Error('Retrieved an empty credential. Verify the account has one set in Safeguard.');
    }

    // --- CRITICAL: Mask the secret in all subsequent log output ---
    maskSecret(secret);

    // --- Set the outputs ---
    core.setOutput('credential', secret);
    core.setOutput(type.output, secret);
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
