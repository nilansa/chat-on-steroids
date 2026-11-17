/**
 * Gives the packaged macOS app a valid ad-hoc seal with a stable designated requirement,
 * and refuses to ship one that is not valid.
 *
 * ## The bug this exists for
 *
 * Issue #66: the 2.0.5 arm64 DMG launched to "the application is damaged" on macOS 27, with
 * Gatekeeper assessment already disabled — so this was a structural failure, not a policy one:
 *
 *     codesign --verify --deep --strict "Chat On Steroids.app"
 *     -> code has no resources but signature indicates they must be present
 *     codesign -dvv -> flags=0x20002(adhoc,linker-signed), Sealed Resources=none
 *
 * `linker-signed` is the giveaway. Every arm64 Mach-O gets an ad-hoc signature from the linker
 * whether anyone asks or not — it is not optional on Apple Silicon. `identity: null` tells
 * electron-builder to skip bundle signing, so the app shipped as a *bundle* carrying signed
 * Mach-Os and no `_CodeSignature/CodeResources`. macOS reads the signature on the executable,
 * looks for the resource seal it implies, finds none, and calls the bundle damaged. There was
 * never an x64-only version of this problem, which is why it appeared with Apple Silicon.
 *
 * ## Why ad-hoc rather than Developer ID
 *
 * The release policy is deliberately unsigned and unnotarized, and this does not change that.
 * An ad-hoc seal carries no Authority and no TeamIdentifier — `codesign -dvv` still reports
 * `Signature=adhoc`, and Gatekeeper still will not vouch for it. What it adds is the resource
 * envelope the executable's own signature already claims exists. The outer app also gets an
 * explicit designated requirement based on its bundle identifier. macOS TCC keys Accessibility
 * and Screen Recording grants to that requirement; the old implicit ad-hoc requirement was the
 * executable cdhash, so every update looked like a new app and invalidated both grants. A stable
 * identifier requirement lets a user grant once and keep that grant across app updates. It is
 * not a trust-bearing certificate and does not make Gatekeeper vouch for the app.
 *
 * ## Why it verifies afterwards
 *
 * The real defect was that nothing checked. The bundle audit asserted the *absence* of a seal, so
 * the broken state was the state the build required, and two releases shipped it. Signing without
 * verifying would leave the same hole one layer along, so a failed verify fails the build.
 */
import { spawnSync } from 'node:child_process';
import { existsSync } from 'node:fs';
import path from 'node:path';
import { assertNoTrustBearingMacCodeSignature } from './macos-audit-utils.mjs';

const UNUSED_MEDIA_PRIVACY_KEYS = [
  'NSCameraUsageDescription',
  'NSMicrophoneUsageDescription',
  'NSAudioCaptureUsageDescription'
];

/** Runs a command and returns its combined output, throwing with that output on failure. */
function run(command, args) {
  const result = spawnSync(command, args, { encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] });
  if (result.error || result.status !== 0) {
    const detail = `${result.stdout ?? ''}${result.stderr ?? ''}`.trim();
    throw new Error(`${command} ${args.join(' ')} failed: ${detail || result.error?.message || result.signal || result.status}`);
  }
  return result;
}

export default async function sealMacOsBundle(context) {
  if (context.electronPlatformName !== 'darwin') return;

  const appName = `${context.packager.appInfo.productFilename}.app`;
  const app = path.join(context.appOutDir, appName);
  if (!existsSync(app)) throw new Error(`afterPack could not find ${app} to seal`);

  const plist = path.join(app, 'Contents', 'Info.plist');
  const originalPlist = JSON.parse(run('plutil', ['-convert', 'json', '-o', '-', plist]).stdout);
  for (const key of UNUSED_MEDIA_PRIVACY_KEYS) {
    if (Object.hasOwn(originalPlist, key)) run('plutil', ['-remove', key, plist]);
  }

  // Electron's generic app template declares camera/microphone/audio capture even when an app
  // never uses those APIs. CoS denies renderer permission requests and has no media-capture
  // feature, so shipping those declarations is misleading and can make macOS surface unrelated
  // privacy prompts. Keep only privacy declarations for capabilities CoS actually exposes.
  const cleanedPlist = JSON.parse(run('plutil', ['-convert', 'json', '-o', '-', plist]).stdout);
  for (const key of UNUSED_MEDIA_PRIVACY_KEYS) {
    if (Object.hasOwn(cleanedPlist, key)) throw new Error(`afterPack failed to remove unused Info.plist key ${key}`);
  }

  // Electron nests frameworks and helper apps that each need their own signature. Seal every
  // nested component first; they keep their own bundle identifiers and default ad-hoc requirements.
  run('codesign', ['--force', '--deep', '--sign', '-', app]);

  // TCC otherwise binds an ad-hoc app's Accessibility/Screen Recording grants to its changing
  // cdhash. Use the app's actual bundle identifier as an explicit, stable designated requirement
  // on the outer app only. Do not apply this requirement to nested helpers/frameworks: each keeps
  // its own identity. This remains ad-hoc (no Authority/TeamIdentifier) and therefore untrusted.
  const bundleId = originalPlist.CFBundleIdentifier;
  if (typeof bundleId !== 'string' || !bundleId.trim()) throw new Error('afterPack could not read CFBundleIdentifier');
  run('codesign', ['--force', '--sign', '-', '--identifier', bundleId,
    '--requirements', `=designated => identifier "${bundleId}"`, app]);

  // The check the two broken releases did not have. --strict so a seal that merely exists is not
  // mistaken for a seal that is coherent, and --deep so a nested framework cannot be the one
  // thing that is wrong, which is exactly how issue #66 presented.
  run('codesign', ['--verify', '--deep', '--strict', '--verbose=2', app]);

  const shown = run('codesign', ['--display', '--verbose=4', app]);
  // Fail loudly if this ever starts producing a trust-bearing signature. The release notes say
  // unsigned, and an afterPack hook silently turning that into something Gatekeeper vouches for
  // would be a policy change smuggled in as a build step.
  // codesign displays these details on stderr even on success. Use the same
  // stdout+stderr policy as the standalone bundle audit, including TeamIdentifier.
  assertNoTrustBearingMacCodeSignature(app, shown, existsSync(path.join(app, 'Contents', '_CodeSignature', 'CodeResources')));

  process.stdout.write(`Sealed ${appName} ad-hoc and verified its resource envelope.\n`);
}
