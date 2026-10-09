import type { Advisory, TechnologyObservation, VulnerabilityMatch } from '@/lib/types';

export async function refreshAdvisories(
  _cursor: string | null,
): Promise<{ advisories: Advisory[]; nextCursor: string | null }> {
  throw new Error('Intel not implemented');
}

export async function match(
  _inventory: TechnologyObservation[],
  _advisories: Advisory[],
): Promise<VulnerabilityMatch[]> {
  throw new Error('Match not implemented');
}
