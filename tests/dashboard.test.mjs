import test from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { PqcDashboardEngine } from '../dist/index.js';

test('ML-KEM Dashboard: Entropy Quality Monitor Assessment', () => {
  const engine = new PqcDashboardEngine();

  // CSPRNG random bytes must achieve EXCELLENT assessment
  const randomSample = randomBytes(4096);
  const metrics = engine.evaluateEntropy(randomSample);

  assert.equal(metrics.sampleCount, 4096);
  assert.ok(metrics.shannonEntropyBits > 7.9, `Shannon entropy should exceed 7.9 bits, got ${metrics.shannonEntropyBits}`);
  assert.equal(metrics.assessment, 'EXCELLENT');

  // Heavily biased bytes must yield low entropy
  const biasedSample = new Uint8Array(4096).fill(0xaa);
  const biasedMetrics = engine.evaluateEntropy(biasedSample);
  assert.equal(biasedMetrics.shannonEntropyBits, 0);
  assert.equal(biasedMetrics.assessment, 'CRITICAL');
});

test('ML-KEM Dashboard: Simulated Key Exchange Telemetry (Pure & Hybrid)', () => {
  const engine = new PqcDashboardEngine();

  // Test Pure ML-KEM-768
  const pureTelemetry = engine.simulateExchange('ML-KEM-768', false);
  assert.equal(pureTelemetry.parameterSet, 'ML-KEM-768');
  assert.equal(pureTelemetry.isHybrid, false);
  assert.equal(pureTelemetry.publicKeyBytes, 1184);
  assert.equal(pureTelemetry.ciphertoBytes, 1088);
  assert.equal(pureTelemetry.verified, true);

  // Test Hybrid ML-KEM-768 + X25519
  const hybridTelemetry = engine.simulateExchange('ML-KEM-768', true);
  assert.equal(hybridTelemetry.parameterSet, 'ML-KEM-768');
  assert.equal(hybridTelemetry.isHybrid, true);
  assert.equal(hybridTelemetry.publicKeyBytes, 1184 + 32);
  assert.equal(hybridTelemetry.ciphertoBytes, 1088 + 32);
  assert.equal(hybridTelemetry.verified, true);
});

test('ML-KEM Dashboard: Parameter Registry Inspection', () => {
  const engine = new PqcDashboardEngine();
  const registry = engine.getParameterRegistry();

  assert.equal(registry.length, 3);
  assert.equal(registry[0].name, 'ML-KEM-512');
  assert.equal(registry[1].name, 'ML-KEM-768');
  assert.equal(registry[2].name, 'ML-KEM-1024');
});

test('ML-KEM Dashboard: HTML Rendering Integrity', () => {
  const engine = new PqcDashboardEngine();
  const html = engine.renderDashboardHtml();

  assert.ok(html.includes('<!DOCTYPE html>'));
  assert.ok(html.includes('QMOOSA Post-Quantum Cryptography Terminal'));
  assert.ok(html.includes('ML-KEM-768'));
  assert.ok(html.includes('Entropy Quality Monitor'));
  assert.ok(html.includes('Simulated Handshake Telemetry'));
});
