import { z } from 'zod';

import { HttpUtil } from '@/utils';

const bitsPerSecond = z.number().int().nonnegative();
const clientBandwidthSchema = z.object({
  available: z.boolean(),
  accountNodeKeys: z.array(z.string()).optional(),
  totalBitsPerSecond: bitsPerSecond,
  nodeBitsPerSecond: z.record(z.string(), bitsPerSecond),
});

export type ClientBandwidth = z.infer<typeof clientBandwidthSchema>;
export type ClientBandwidthPolicy = Omit<ClientBandwidth, 'available' | 'accountNodeKeys'>;

function bandwidthPath(email: string) {
  return `/panel/api/clients/${encodeURIComponent(email)}/bandwidth`;
}

export async function fetchClientBandwidth(email: string, signal: AbortSignal) {
  const msg = await HttpUtil.get(bandwidthPath(email), undefined, { signal, silent: true });
  if (!msg.success) throw new Error(msg.msg);
  return clientBandwidthSchema.parse(msg.obj);
}

export function saveClientBandwidth(email: string, policy: ClientBandwidthPolicy) {
  return HttpUtil.post(bandwidthPath(email), policy, {
    headers: { 'Content-Type': 'application/json' },
    silent: true,
  });
}
