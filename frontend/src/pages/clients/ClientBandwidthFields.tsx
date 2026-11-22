import { Alert, Button, Form, InputNumber, Space, Spin, Typography } from 'antd';
import { useId } from 'react';
import { useTranslation } from 'react-i18next';

import type { ClientBandwidth, ClientBandwidthPolicy } from '@/api/queries/clientBandwidth';
import { useNodesQuery } from '@/api/queries/useNodesQuery';
import type { InboundOption } from '@/schemas/client';

function formatMbps(bitsPerSecond: number) {
  const digits = String(bitsPerSecond).padStart(7, '0');
  const fraction = digits.slice(-6).replace(/0+$/, '');
  return fraction ? `${digits.slice(0, -6)}.${fraction}` : digits.slice(0, -6);
}

function parseMbps(megabitsPerSecond: string) {
  if (!/^\d+(\.\d{0,6})?$/.test(megabitsPerSecond)) return undefined;
  const [whole, fraction = ''] = megabitsPerSecond.split('.');
  const bitsPerSecond = Number(`${whole}${fraction.padEnd(6, '0')}`);
  return Number.isSafeInteger(bitsPerSecond) ? bitsPerSecond : undefined;
}

export function getBandwidthNodeKeys(
  inbounds: InboundOption[],
  inboundIds: number[],
  accountNodeKeys: string[] = [],
) {
  const inboundSet = new Set(inboundIds);
  const nodeKeys = new Set(accountNodeKeys);
  for (const inbound of inbounds) {
    if (inboundSet.has(inbound.id) && inbound.bandwidthNodeKey) {
      nodeKeys.add(inbound.bandwidthNodeKey);
    }
  }
  return nodeKeys;
}

interface RateFieldProps {
  id: string;
  label: string;
  hint?: string;
  value: number | undefined;
  disabled: boolean;
  onChange: (value: number | undefined) => void;
}

function RateField({ id, label, hint, value, disabled, onChange }: RateFieldProps) {
  const { t } = useTranslation();
  return (
    <Form.Item htmlFor={id} label={label} extra={hint}>
      <InputNumber<string>
        id={id}
        stringMode
        min="0"
        max={formatMbps(Number.MAX_SAFE_INTEGER)}
        precision={6}
        value={value === undefined ? null : formatMbps(value)}
        placeholder={t('pages.clients.bandwidth.inherit')}
        suffix="Mbps"
        disabled={disabled}
        style={{ width: '100%' }}
        onChange={(next) => {
          if (next === null) {
            onChange(undefined);
          } else {
            const rate = parseMbps(next);
            if (rate !== undefined) onChange(rate);
          }
        }}
      />
    </Form.Item>
  );
}

interface Props {
  policy: ClientBandwidth | undefined;
  inbounds: InboundOption[];
  inboundIds: number[];
  loading: boolean;
  disabled: boolean;
  onRetry: () => void;
  onChange: (draft: ClientBandwidthPolicy) => void;
}

export default function ClientBandwidthFields({
  policy,
  inbounds,
  inboundIds,
  loading,
  disabled,
  onRetry,
  onChange,
}: Props) {
  const { t } = useTranslation();
  const id = useId();
  const { nodes } = useNodesQuery();
  const nodeKeys = getBandwidthNodeKeys(inbounds, inboundIds, policy?.accountNodeKeys);

  if (!policy) {
    return loading ? (
      <Spin />
    ) : (
      <Alert
        showIcon
        type="error"
        title={t('pages.clients.bandwidth.loadError')}
        action={<Button onClick={onRetry}>{t('refresh')}</Button>}
      />
    );
  }

  const nodeFields = [...nodeKeys].map((key) => {
    const via = /^via:(\d+):(\d+)$/.exec(key);
    const node = nodes.find((node) =>
      via ? String(node.id) === via[1] : `guid:${node.guid}` === key || `node:${node.id}` === key,
    );
    const nodeLabel =
      key === 'local' ? t('pages.clients.bandwidth.local') : node?.name || node?.address;
    const label = via
      ? t('pages.clients.bandwidth.nodeVia', { id: via[2], name: nodeLabel || via[1] })
      : nodeLabel || key;
    return { key, label, address: node?.address };
  });

  return (
    <Space orientation="vertical" size="middle" style={{ display: 'flex' }}>
      {!policy.available && (
        <Alert showIcon type="warning" title={t('pages.clients.bandwidth.unavailable')} />
      )}
      <RateField
        id={`${id}-total`}
        label={t('pages.clients.bandwidth.total')}
        hint={t('pages.clients.bandwidth.totalHint')}
        value={policy.totalBitsPerSecond}
        disabled={disabled}
        onChange={(value) =>
          onChange({
            totalBitsPerSecond: value ?? 0,
            nodeBitsPerSecond: policy.nodeBitsPerSecond,
          })
        }
      />
      <section>
        <Typography.Title level={5}>{t('pages.clients.bandwidth.nodes')}</Typography.Title>
        {nodeKeys.size === 0 ? (
          <Typography.Text type="secondary">{t('pages.clients.bandwidth.noNodes')}</Typography.Text>
        ) : (
          <>
            <Typography.Paragraph type="secondary">
              {t('pages.clients.bandwidth.nodeHint')}
            </Typography.Paragraph>
            {nodeFields.map(({ key, label, address }) => (
              <RateField
                key={key}
                id={`${id}-${key}`}
                label={label}
                hint={
                  nodeFields.some((other) => other.key !== key && other.label === label)
                    ? address || key
                    : undefined
                }
                value={policy.nodeBitsPerSecond[key]}
                disabled={disabled}
                onChange={(value) => {
                  const nodeBitsPerSecond = { ...policy.nodeBitsPerSecond };
                  if (value === undefined) delete nodeBitsPerSecond[key];
                  else nodeBitsPerSecond[key] = value;
                  onChange({ totalBitsPerSecond: policy.totalBitsPerSecond, nodeBitsPerSecond });
                }}
              />
            ))}
          </>
        )}
      </section>
    </Space>
  );
}
