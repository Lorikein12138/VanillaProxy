import { z } from 'zod';

// HTTP proxy inbound — a classic forward proxy. Accounts are user/pass pairs;
// `allowTransparent` exposes Xray's option to forward requests with the
// original Host header. The optional client ID belongs to the panel only.
export const HttpAccountSchema = z.object({
  user: z.string().min(1),
  pass: z.string().min(1),
  bandwidthClientId: z
    .number()
    .int()
    .positive()
    .nullable()
    .transform((id) => id ?? undefined)
    .optional(),
});
export type HttpAccount = z.infer<typeof HttpAccountSchema>;

export const HttpInboundSettingsSchema = z.object({
  accounts: z.array(HttpAccountSchema).default([]),
  allowTransparent: z.boolean().default(false),
});
export type HttpInboundSettings = z.infer<typeof HttpInboundSettingsSchema>;
