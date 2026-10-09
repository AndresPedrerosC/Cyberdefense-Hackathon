import type { Scope, VerificationJob, VerificationResult, VulnerabilityMatch } from '@/lib/types';

export async function planChecks(_matches: VulnerabilityMatch[], _scope: Scope): Promise<VerificationJob[]> {
  return [];
}

export async function verify(_job: VerificationJob): Promise<VerificationResult> {
  throw new Error('Verify not implemented');
}
