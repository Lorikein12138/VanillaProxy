import { useTranslation } from 'react-i18next';
import { Button, Form, Input, Select, Space } from 'antd';
import { MinusOutlined, PlusOutlined } from '@ant-design/icons';
import { useFieldArray, useFormContext, useWatch } from 'react-hook-form';

import { useClientIDOptions } from '@/api/queries/useClientOptions';
import { RandomUtil } from '@/utils';
import { InputAddon } from '@/components/ui';
import { FormField } from '@/components/form/rhf';

export default function AccountsList({
  protocol,
  allowBandwidthBinding,
}: {
  protocol: 'http' | 'mixed';
  allowBandwidthBinding: boolean;
}) {
  const { t } = useTranslation();
  const { control } = useFormContext();
  const { fields, append, remove } = useFieldArray({ control, name: 'settings.accounts' });
  const auth = useWatch({ control, name: 'settings.auth' });
  const canBind = allowBandwidthBinding && (protocol === 'http' || auth === 'password');
  const clients = useClientIDOptions(canBind && fields.length > 0);
  const clientLabel = `${t('pages.clients.bandwidth.tab')} · ${t('pages.clients.client')}`;
  return (
    <>
      <Form.Item label={t('pages.inbounds.form.accounts')}>
        <Button
          size="small"
          onClick={() =>
            append({
              user: RandomUtil.randomLowerAndNum(8),
              pass: RandomUtil.randomLowerAndNum(12),
            })
          }
        >
          <PlusOutlined aria-hidden /> {t('add')}
        </Button>
      </Form.Item>
      {fields.length > 0 && (
        <Form.Item wrapperCol={{ span: 24 }}>
          {fields.map((field, idx) => (
            <Space.Compact key={field.id} className="mb-8" block>
              <InputAddon>{String(idx + 1)}</InputAddon>
              <FormField name={['settings', 'accounts', idx, 'user']} noStyle>
                <Input aria-label={`${t('username')} ${idx + 1}`} placeholder={t('username')} />
              </FormField>
              <FormField name={['settings', 'accounts', idx, 'pass']} noStyle>
                <Input aria-label={`${t('password')} ${idx + 1}`} placeholder={t('password')} />
              </FormField>
              {canBind && (
                <FormField
                  name={['settings', 'accounts', idx, 'bandwidthClientId']}
                  transform={{ output: (value) => value ?? null }}
                  noStyle
                >
                  <Select
                    aria-label={`${clientLabel} ${idx + 1}`}
                    placeholder={clientLabel}
                    allowClear
                    showSearch={{ optionFilterProp: 'label' }}
                    loading={clients.isPending && clients.isFetching}
                    options={clients.data}
                    style={{ minWidth: 150, flex: 1 }}
                  />
                </FormField>
              )}
              <Button aria-label={t('remove')} onClick={() => remove(idx)}>
                <MinusOutlined aria-hidden />
              </Button>
            </Space.Compact>
          ))}
        </Form.Item>
      )}
    </>
  );
}
