// SPDX-License-Identifier: MIT

import { describe, expect, it } from 'vitest';
import {
  normalizeImportedSbom,
  buildScannerResultFromImport,
  hashSbomDocument
} from '../worker/src/sbom-import.js';

describe('SBOM import normalization', () => {
  it('normalizes CycloneDX components and deduplicates packages', () => {
    const result = normalizeImportedSbom({
      format: 'CycloneDX',
      document: {
        bomFormat: 'CycloneDX',
        specVersion: '1.5',
        components: [
          {
            bomRef: 'pkg:npm/example@1.0.0',
            name: 'example',
            version: '1.0.0',
            purl: 'pkg:npm/example@1.0.0',
            licenses: [{ license: { id: 'MIT' } }]
          },
          {
            bomRef: 'duplicate',
            name: 'example',
            version: '1.0.0',
            purl: 'pkg:npm/example@1.0.0'
          }
        ]
      }
    });

    expect(result.format).toBe('CycloneDX');
    expect(result.packages).toHaveLength(1);
    expect(result.licenses).toHaveLength(1);
    expect(result.packages[0]?.ecosystem).toBe('npm');

    const scannerResult = buildScannerResultFromImport(result);
    expect(scannerResult.packages[0]?.purl).toBe('pkg:npm/example@1.0.0');
    expect(hashSbomDocument(result.bom)).toMatch(/^[a-f0-9]{64}$/u);
  });

  it('normalizes SPDX packages and preserves declared licenses', () => {
    const result = normalizeImportedSbom({
      format: 'SPDX',
      document: {
        spdxVersion: 'SPDX-2.3',
        packages: [
          {
            name: 'example-lib',
            versionInfo: '2.0.0',
            licenseConcluded: 'GPL-3.0-only OR MIT',
            externalRefs: [
              {
                referenceType: 'purl',
                referenceLocator: 'pkg:pypi/example-lib@2.0.0'
              }
            ]
          }
        ]
      }
    });

    expect(result.format).toBe('SPDX');
    expect(result.packages).toHaveLength(1);
    expect(result.packages[0]?.purl).toBe('pkg:pypi/example-lib@2.0.0');
    expect(result.packages[0]?.ecosystem).toBe('pypi');
    expect(result.licenses.map((item) => item.spdxId)).toEqual(['GPL-3.0-only', 'MIT']);

    const scannerResult = buildScannerResultFromImport(result);
    expect(scannerResult.bom.components).toEqual([
      {
        bomRef: 'pkg:pypi/example-lib@2.0.0',
        name: 'example-lib',
        version: '2.0.0',
        type: 'library',
        purl: 'pkg:pypi/example-lib@2.0.0',
        licenses: [{ license: { id: 'GPL-3.0-only' } }, { license: { id: 'MIT' } }]
      }
    ]);
  });

  it('throws for unsupported formats', () => {
    expect(() => normalizeImportedSbom({ format: 'Unknown', document: {} })).toThrow(/Unsupported SBOM format/u);
  });
});

