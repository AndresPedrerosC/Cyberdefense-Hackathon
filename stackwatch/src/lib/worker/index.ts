import type { Run } from '@/lib/types';

export async function executeRun(_run: Run): Promise<void> {
  throw new Error('Worker not implemented');
}
