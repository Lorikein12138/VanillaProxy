import { fireEvent, screen, waitFor } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';

import ClientFormModal from '@/pages/clients/ClientFormModal';
import { HttpUtil, Msg } from '@/utils';
import { renderWithProviders } from './test-utils';

vi.mock('@/api/queries/useNodesQuery', () => ({
  useNodesQuery: () => ({
    nodes: [
      { id: 10, guid: 'first', name: 'CN2GIA' },
      { id: 11, guid: 'second', name: 'CN2GIA', transitive: true },
      { id: 12, name: 'TRANSFER' },
      { id: 20, name: 'Reattached node' },
    ],
  }),
}));

const client = { email: 'client@example.com', enable: true, subId: 'subid123' };
const policy = {
  available: false,
  totalBitsPerSecond: 0,
  nodeBitsPerSecond: { 'node:10': 2_000_000, 'node:20': 500_000, 'via:12:21': 750_000 },
};

const bandwidthPath = (email: string) =>
  `/panel/api/clients/${encodeURIComponent(email)}/bandwidth`;

function renderEdit(attachedIds = [1, 2, 3, 4, 5, 8]) {
  const save = vi.fn().mockResolvedValue({ success: true });
  const close = vi.fn();
  renderWithProviders(
    <ClientFormModal
      open
      mode="edit"
      client={client}
      attachedIds={attachedIds}
      inbounds={[
        { id: 1, protocol: 'vless', nodeId: 10, bandwidthNodeKey: 'node:10' },
        { id: 2, protocol: 'amneziawg', nodeId: 10, bandwidthNodeKey: 'node:10' },
        { id: 3, protocol: 'trojan', nodeId: 10, bandwidthNodeKey: 'guid:second' },
        { id: 4, protocol: 'tuic', nodeId: 12, bandwidthNodeKey: 'node:12' },
        { id: 5, protocol: 'vless', bandwidthNodeKey: 'local' },
        { id: 6, protocol: 'vless', enable: true, nodeId: 20, bandwidthNodeKey: 'node:20' },
        { id: 7, protocol: 'trojan', enable: true, nodeId: 12, bandwidthNodeKey: 'via:12:21' },
        { id: 8, protocol: 'mtproto', nodeId: 10, bandwidthNodeKey: 'node:10' },
      ]}
      save={save}
      onOpenChange={close}
    />,
  );
  return { save, close };
}

function editRate(field: HTMLElement, value: string) {
  fireEvent.change(field, { target: { value } });
  fireEvent.blur(field);
}

describe('client bandwidth policy', () => {
  afterEach(() => vi.restoreAllMocks());

  it('saves the local cap for a client linked only through a proxy account', async () => {
    const mapped = { ...policy, accountNodeKeys: ['local'], nodeBitsPerSecond: {} };
    vi.spyOn(HttpUtil, 'get').mockImplementation(async (path) => {
      if (path === bandwidthPath(client.email)) return new Msg(true, '', mapped);
      return new Msg(false);
    });
    const post = vi.spyOn(HttpUtil, 'post').mockResolvedValue(new Msg(true, '', mapped));
    const { save, close } = renderEdit([]);

    fireEvent.click(screen.getByRole('tab', { name: 'Bandwidth' }));
    editRate(await screen.findByRole('spinbutton', { name: 'Local panel' }), '2');
    fireEvent.click(screen.getByRole('button', { name: 'Save' }));

    await waitFor(() => expect(close).toHaveBeenCalledWith(false));
    expect(post).toHaveBeenCalledWith(
      bandwidthPath(client.email),
      { totalBitsPerSecond: 0, nodeBitsPerSecond: { local: 2_000_000 } },
      expect.anything(),
    );
    expect(save).not.toHaveBeenCalled();
  });

  it('uses the physical node key and preserves the difference between an explicit zero and inheritance', async () => {
    const get = vi.spyOn(HttpUtil, 'get').mockImplementation(async (path) => {
      if (path === bandwidthPath(client.email)) return new Msg(true, '', policy);
      return new Msg(false);
    });
    const post = vi.spyOn(HttpUtil, 'post').mockResolvedValue(new Msg(true, '', policy));
    const { save, close } = renderEdit();

    expect(get).not.toHaveBeenCalledWith(bandwidthPath(client.email), undefined, expect.anything());
    fireEvent.click(screen.getByRole('tab', { name: 'Bandwidth' }));

    const total = await screen.findByRole('spinbutton', { name: 'Total bandwidth cap' });
    const [first, second] = screen.getAllByRole('spinbutton', { name: 'CN2GIA' });
    expect(screen.getAllByRole('spinbutton', { name: 'CN2GIA' })).toHaveLength(2);
    expect(screen.getByRole('spinbutton', { name: 'TRANSFER' })).toBeTruthy();
    expect(screen.getByRole('spinbutton', { name: 'Local panel' })).toBeTruthy();
    expect(screen.queryByRole('spinbutton', { name: 'Reattached node' })).toBeNull();
    expect(screen.getByText(/outside the running bandwidth limiter/)).toBeTruthy();

    editRate(total, '12.345678');
    editRate(first, '');
    editRate(second, '0');
    fireEvent.click(screen.getByRole('button', { name: 'Save' }));

    await waitFor(() => expect(close).toHaveBeenCalledWith(false));
    expect(post).toHaveBeenCalledWith(
      bandwidthPath(client.email),
      { totalBitsPerSecond: 12_345_678, nodeBitsPerSecond: { 'guid:second': 0 } },
      expect.anything(),
    );
    expect(save).not.toHaveBeenCalled();
  });

  it('retries a failed policy save with the new email and keeps the saved client edit', async () => {
    vi.spyOn(HttpUtil, 'get').mockImplementation(async (path) => {
      if (path === bandwidthPath(client.email)) return new Msg(true, '', policy);
      return new Msg(false);
    });
    const savePolicy = vi
      .fn()
      .mockResolvedValueOnce(new Msg(false, 'Policy storage is unavailable'))
      .mockResolvedValueOnce(new Msg(true, '', policy));
    const post = vi.spyOn(HttpUtil, 'post').mockImplementation(async (path) => {
      if (path.endsWith('/bandwidth')) return savePolicy();
      return new Msg(false);
    });
    const { save, close } = renderEdit();
    const nextEmail = 'renamed+user@example.com';

    fireEvent.change(screen.getByLabelText('Email'), { target: { value: nextEmail } });
    fireEvent.click(screen.getByRole('tab', { name: 'Bandwidth' }));
    editRate(await screen.findByRole('spinbutton', { name: 'Total bandwidth cap' }), '3');
    fireEvent.click(screen.getByRole('button', { name: 'Save' }));

    await screen.findByText('Policy storage is unavailable');
    expect(close).not.toHaveBeenCalled();
    await waitFor(() =>
      expect(screen.getByRole('button', { name: 'Cancel' }).hasAttribute('disabled')).toBe(false),
    );
    fireEvent.click(screen.getByRole('button', { name: /Save$/ }));
    await waitFor(() => expect(close).toHaveBeenCalledWith(false));

    expect(save).toHaveBeenCalledTimes(1);
    const policyPaths = post.mock.calls
      .map(([path]) => path)
      .filter((path) => path.endsWith('/bandwidth'));
    expect(policyPaths).toEqual([bandwidthPath(nextEmail), bandwidthPath(nextEmail)]);
  });

  it('uses pending inbound changes and omits previously edited nodes after detach', async () => {
    vi.spyOn(HttpUtil, 'get').mockImplementation(async (path) => {
      if (path === bandwidthPath(client.email)) return new Msg(true, '', policy);
      return new Msg(false);
    });
    const post = vi.spyOn(HttpUtil, 'post').mockResolvedValue(new Msg(true, '', policy));
    const { save, close } = renderEdit();
    fireEvent.click(screen.getByRole('tab', { name: 'Bandwidth' }));
    editRate(await screen.findByRole('spinbutton', { name: 'Total bandwidth cap' }), '3');
    editRate(screen.getByRole('spinbutton', { name: 'TRANSFER' }), '2');

    fireEvent.click(screen.getByRole('tab', { name: 'Basics' }));
    fireEvent.click(screen.getByRole('button', { name: 'Clear all' }));
    fireEvent.click(screen.getByRole('tab', { name: 'Bandwidth' }));
    expect(screen.getByText('No nodes are associated with the selected inbounds.')).toBeTruthy();
    fireEvent.click(screen.getByRole('button', { name: 'Save' }));

    await waitFor(() => expect(close).toHaveBeenCalledWith(false));
    expect(save.mock.calls[0][1].detach).toEqual([1, 2, 3, 4, 5, 8]);
    expect(post).toHaveBeenCalledWith(
      bandwidthPath(client.email),
      { totalBitsPerSecond: 3_000_000, nodeBitsPerSecond: {} },
      expect.anything(),
    );
  });

  it('shows stored historical limits only after the nodes are selected again', async () => {
    vi.spyOn(HttpUtil, 'get').mockImplementation(async (path) => {
      if (path === bandwidthPath(client.email)) return new Msg(true, '', policy);
      return new Msg(false);
    });
    const post = vi.spyOn(HttpUtil, 'post').mockResolvedValue(new Msg(true, '', policy));
    const { save, close } = renderEdit();

    fireEvent.click(screen.getByRole('tab', { name: 'Bandwidth' }));
    editRate(await screen.findByRole('spinbutton', { name: 'Total bandwidth cap' }), '5');
    expect(screen.queryByRole('spinbutton', { name: 'Reattached node' })).toBeNull();
    expect(screen.queryByRole('spinbutton', { name: 'Node 21 via TRANSFER' })).toBeNull();

    fireEvent.click(screen.getByRole('tab', { name: 'Basics' }));
    fireEvent.click(screen.getByRole('button', { name: 'Select all' }));
    fireEvent.click(screen.getByRole('tab', { name: 'Bandwidth' }));
    const reattached = screen.getByRole<HTMLInputElement>('spinbutton', {
      name: 'Reattached node',
    });
    const downstream = screen.getByRole<HTMLInputElement>('spinbutton', {
      name: 'Node 21 via TRANSFER',
    });
    expect(Number(reattached.value)).toBe(0.5);
    expect(Number(downstream.value)).toBe(0.75);
    fireEvent.click(screen.getByRole('button', { name: 'Save' }));

    await waitFor(() => expect(close).toHaveBeenCalledWith(false));
    expect(save.mock.calls[0][1].attach).toEqual([6, 7]);
    expect(post).toHaveBeenCalledWith(
      bandwidthPath(client.email),
      { totalBitsPerSecond: 5_000_000, nodeBitsPerSecond: policy.nodeBitsPerSecond },
      expect.anything(),
    );
    const policyCall = post.mock.calls.findIndex(([path]) => path === bandwidthPath(client.email));
    expect(save.mock.invocationCallOrder[0]).toBeLessThan(
      post.mock.invocationCallOrder[policyCall],
    );
  });

  it('validates the node caps against the total before saving client details', async () => {
    vi.spyOn(HttpUtil, 'get').mockImplementation(async (path) => {
      if (path === bandwidthPath(client.email)) return new Msg(true, '', policy);
      return new Msg(false);
    });
    const { save } = renderEdit();
    fireEvent.click(screen.getByRole('tab', { name: 'Bandwidth' }));
    editRate(await screen.findByRole('spinbutton', { name: 'Total bandwidth cap' }), '1');
    fireEvent.click(screen.getByRole('button', { name: 'Save' }));

    await screen.findByText('A node bandwidth cap cannot exceed the total bandwidth cap.');
    expect(save).not.toHaveBeenCalled();
  });
});
