export interface RealLedgerState {
  balances: Record<string, number>
  merkleSize: number
  merkleRoot: string
  nullifiers: string[]
}

async function apiFetch<T>(path: string): Promise<T> {
  const res = await fetch(`/api${path}`)
  if (!res.ok) throw new Error(`HTTP ${res.status}`)
  return res.json() as Promise<T>
}

export async function fetchLedgerState(): Promise<RealLedgerState> {
  const [balancesResp, treeResp, nullifiersResp] = await Promise.all([
    apiFetch<{ balances: Record<string, number> }>('/balances'),
    apiFetch<{ root: string | number; size: number }>('/tree'),
    apiFetch<{ nullifiers: (string | number)[] }>('/nullifiers'),
  ])

  return {
    balances: balancesResp.balances,
    merkleSize: treeResp.size,
    merkleRoot: String(treeResp.root),
    nullifiers: nullifiersResp.nullifiers.map(String),
  }
}

// ─── Wallet-server (port 8081) ─────────────────────────────────────────────

async function walletFetch<T>(path: string, init?: RequestInit): Promise<T> {
  const res = await fetch(`/wallet${path}`, init)
  if (!res.ok) {
    const text = await res.text().catch(() => '')
    throw new Error(`HTTP ${res.status}${text ? ': ' + text : ''}`)
  }
  return res.json() as Promise<T>
}

export async function getWalletBalance(): Promise<number> {
  const r = await walletFetch<{ private_balance: number }>('/balance')
  return r.private_balance
}

export async function getWalletAddress(): Promise<Record<string, unknown>> {
  return walletFetch('/address', { method: 'POST' })
}

export async function walletShield(sender: string, amount: number): Promise<void> {
  await walletFetch('/shield', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ sender, amount }),
  })
}

export async function walletTransfer(to: unknown, amount: number): Promise<void> {
  await walletFetch('/transfer', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ to, amount }),
  })
}

export async function walletUnshield(recipient: string, amount: number): Promise<void> {
  await walletFetch('/unshield', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ recipient, amount }),
  })
}

export async function walletScan(): Promise<{ found: number; spent: number }> {
  return walletFetch('/scan', { method: 'POST' })
}
