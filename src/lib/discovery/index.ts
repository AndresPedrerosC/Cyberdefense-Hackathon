import type { Target, TechnologyObservation } from '@/lib/types';

export async function discover(_target: Target): Promise<TechnologyObservation[]> {
  throw new Error('Discovery not implemented');
}
