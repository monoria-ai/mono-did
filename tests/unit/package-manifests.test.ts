import { describe, expect, it } from 'vitest';
import { readdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';

interface PackageJson {
  name?: string;
  dependencies?: Record<string, string>;
  devDependencies?: Record<string, string>;
  peerDependencies?: Record<string, string>;
}

function collectDependencySpecifiers(pkg: PackageJson): string[] {
  const fields = [pkg.dependencies, pkg.devDependencies, pkg.peerDependencies];
  return fields
    .flatMap((field) => Object.values(field ?? {}));
}

describe('package manifests', () => {
  it('does not use file: dependency specifiers in publishable mono-did packages', () => {
    const packagesRoot = join(process.cwd(), 'packages');
    const packageDirs = readdirSync(packagesRoot, { withFileTypes: true })
      .filter((entry) => entry.isDirectory())
      .map((entry) => entry.name);

    for (const packageDir of packageDirs) {
      const manifestPath = join(packagesRoot, packageDir, 'package.json');
      const manifest = JSON.parse(readFileSync(manifestPath, 'utf8')) as PackageJson;
      const specifiers = collectDependencySpecifiers(manifest);

      for (const specifier of specifiers) {
        expect(specifier.startsWith('file:'), `${manifest.name ?? packageDir}: ${specifier}`).toBe(false);
      }
    }
  });
});
