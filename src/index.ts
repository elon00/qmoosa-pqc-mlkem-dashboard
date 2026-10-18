import { randomBytes } from 'node:crypto';
import {
  ML_KEM_512,
  ML_KEM_768,
  ML_KEM_1024,
  getMlKemParameters,
  type MlKemParameterName,
  type MlKemParameters
} from '@qmoosa/pqc-mlkem-protocol';
import {
  MlKemClient,
  PqcSessionHandshake,
  bytesToHex
} from '@qmoosa/pqc-mlkem-sdk';

export interface EntropyMetrics {
  readonly sampleCount: number;
  readonly shannonEntropyBits: number;
  readonly minEntropyBits: number;
  readonly chiSquared: number;
  readonly assessment: 'EXCELLENT' | 'ACCEPTABLE' | 'DEGRADED' | 'CRITICAL';
}

export interface HandshakeTelemetry {
  readonly sessionId: string;
  readonly parameterSet: MlKemParameterName;
  readonly isHybrid: boolean;
  readonly publicKeyBytes: number;
  readonly ciphertoBytes: number;
  readonly sharedSecretPreviewHex: string;
  readonly latencyMs: number;
  readonly verified: boolean;
}

export class PqcDashboardEngine {
  private readonly client: MlKemClient;

  constructor(client?: MlKemClient) {
    this.client = client ?? new MlKemClient();
  }

  /**
   * Evaluates the statistical entropy quality of random seed bytes
   */
  public evaluateEntropy(samples: Uint8Array): EntropyMetrics {
    if (!samples || samples.length === 0) {
      throw new Error('INVALID_SAMPLES: Samples array must not be empty');
    }

    const counts = new Uint32Array(256);
    for (let i = 0; i < samples.length; i++) {
      counts[samples[i]]++;
    }

    const n = samples.length;
    let shannon = 0;
    let maxProb = 0;
    const expected = n / 256;
    let chiSq = 0;

    for (let i = 0; i < 256; i++) {
      const c = counts[i];
      if (c > 0) {
        const p = c / n;
        shannon -= p * Math.log2(p);
        if (p > maxProb) maxProb = p;
      }
      const diff = c - expected;
      chiSq += (diff * diff) / expected;
    }

    const minEntropy = maxProb > 0 ? -Math.log2(maxProb) : 0;

    let assessment: 'EXCELLENT' | 'ACCEPTABLE' | 'DEGRADED' | 'CRITICAL' = 'CRITICAL';
    if (shannon >= 7.95) {
      assessment = 'EXCELLENT';
    } else if (shannon >= 7.5) {
      assessment = 'ACCEPTABLE';
    } else if (shannon >= 6.0) {
      assessment = 'DEGRADED';
    }

    return Object.freeze({
      sampleCount: n,
      shannonEntropyBits: Number(shannon.toFixed(4)),
      minEntropyBits: Number(minEntropy.toFixed(4)),
      chiSquared: Number(chiSq.toFixed(2)),
      assessment
    });
  }

  /**
   * Simulates an end-to-end post-quantum key exchange session with telemetry
   */
  public simulateExchange(
    paramName: MlKemParameterName = ML_KEM_768.name,
    isHybrid = true
  ): HandshakeTelemetry {
    const params = getMlKemParameters(paramName);
    const sessionId = `pqc-sim-${Date.now()}`;
    const start = performance.now();

    let verified = false;
    let pkBytes = 0;
    let cBytes = 0;
    let secretPreview = '';

    if (isHybrid) {
      const alice = this.client.createHybridKeyPair(paramName);
      pkBytes = params.encapsulationKeyBytes + 32;

      const hello = PqcSessionHandshake.createClientHello(sessionId, alice);
      const { serverHello, serverSessionKeyHex } = PqcSessionHandshake.processClientHelloAndCreateServerHello(
        this.client,
        hello
      );
      cBytes = params.ciphertextBytes + 32;

      const { clientConfirmation, clientSessionKeyHex } = PqcSessionHandshake.processServerHelloAndConfirm(
        this.client,
        {
          pqcDecapsulationKeyHex: alice.pqcDecapsulationKeyHex,
          ecdhPrivateKeyHex: alice.ecdhPrivateKeyHex
        },
        serverHello,
        paramName
      );

      const confirmed = PqcSessionHandshake.verifyClientConfirmation(serverSessionKeyHex, sessionId, clientConfirmation);
      verified = confirmed && clientSessionKeyHex === serverSessionKeyHex;
      secretPreview = clientSessionKeyHex.slice(0, 16) + '...';
    } else {
      const alice = this.client.createKeyPair(paramName);
      pkBytes = params.encapsulationKeyBytes;

      const bob = this.client.encapsulateSecret(alice.encapsulationKeyHex, paramName);
      cBytes = params.ciphertextBytes;

      const aliceKey = this.client.decapsulateSecret(alice.decapsulationKeyHex, bob.ciphertextHex, paramName);
      verified = aliceKey === bob.sharedSecretHex;
      secretPreview = aliceKey.slice(0, 16) + '...';
    }

    const latencyMs = Number((performance.now() - start).toFixed(2));

    return Object.freeze({
      sessionId,
      parameterSet: paramName,
      isHybrid,
      publicKeyBytes: pkBytes,
      ciphertoBytes: cBytes,
      sharedSecretPreviewHex: secretPreview,
      latencyMs,
      verified
    });
  }

  /**
   * Returns current protocol parameter registry for dashboard visualization
   */
  public getParameterRegistry(): readonly Readonly<MlKemParameters>[] {
    return Object.freeze([ML_KEM_512, ML_KEM_768, ML_KEM_1024]);
  }

  /**
   * Renders the Web4 responsive dashboard HTML
   */
  public renderDashboardHtml(): string {
    const registry = this.getParameterRegistry();
    const entropySample = randomBytes(4096);
    const entropyMetrics = this.evaluateEntropy(entropySample);
    const simTelemetry = this.simulateExchange('ML-KEM-768', true);

    return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>QMOOSA Post-Quantum Cryptography Terminal</title>
  <style>
    body { font-family: monospace; background: #0a0e17; color: #00ffcc; margin: 0; padding: 24px; }
    h1 { color: #00ffff; border-bottom: 2px solid #00ffcc; padding-bottom: 8px; }
    .card { background: #131c2d; border: 1px solid #1f304f; border-radius: 8px; padding: 16px; margin-bottom: 16px; }
    .status-ok { color: #00ff88; font-weight: bold; }
    table { width: 100%; border-collapse: collapse; margin-top: 8px; }
    th, td { text-align: left; padding: 8px; border-bottom: 1px solid #1f304f; }
    th { color: #88ccff; }
  </style>
</head>
<body>
  <h1>QMOOSA Post-Quantum Cryptography Terminal (FIPS 203)</h1>
  <div class="card">
    <h3>Entropy Quality Monitor</h3>
    <p>Sample Size: ${entropyMetrics.sampleCount} bytes | Shannon Entropy: ${entropyMetrics.shannonEntropyBits} / 8.0 bits</p>
    <p>Status: <span class="status-ok">${entropyMetrics.assessment}</span> (Chi^2: ${entropyMetrics.chiSquared})</p>
  </div>
  <div class="card">
    <h3>Simulated Handshake Telemetry</h3>
    <p>Session ID: ${simTelemetry.sessionId} | Parameter: ${simTelemetry.parameterSet} (Hybrid: ${simTelemetry.isHybrid})</p>
    <p>Public Key: ${simTelemetry.publicKeyBytes} B | Ciphertext: ${simTelemetry.ciphertoBytes} B | Latency: ${simTelemetry.latencyMs} ms</p>
    <p>Handshake Status: <span class="status-ok">${simTelemetry.verified ? 'ESTABLISHED (AUTHENTICATED)' : 'FAILED'}</span></p>
  </div>
  <div class="card">
    <h3>NIST FIPS 203 Parameter Sets</h3>
    <table>
      <tr><th>Standard</th><th>Rank k</th><th>Public Key</th><th>Ciphertext</th><th>Category</th></tr>
      ${registry.map(p => `<tr><td>${p.name}</td><td>${p.k}</td><td>${p.encapsulationKeyBytes} B</td><td>${p.ciphertextBytes} B</td><td>${p.claimedSecurity}</td></tr>`).join('')}
    </table>
  </div>
</body>
</html>`;
  }
}
