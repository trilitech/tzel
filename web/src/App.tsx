import { useState, useEffect, useCallback, useRef } from 'react'
import type { MockWalletState, TxType, ProofInfo, Contact } from './types'
import {
  INITIAL_STATE, PROOF_SPEED_PRESETS, INJECT_DELAY_MS, VERIFY_DELAY_MS,
  privateBalance, applyShield, applyTransfer, applyUnshield,
  type ProofSpeed,
} from './mockService'
import {
  fetchLedgerState, type RealLedgerState,
  getWalletBalance, getWalletAddress,
  walletShield, walletTransfer, walletUnshield, walletScan,
} from './realService'
import { useAddressBook } from './useAddressBook'

type Mode = 'mock' | 'real'
type ProvingPhase = 'idle' | 'generating' | 'injecting' | 'verifying' | 'done'

function truncateHex(hex: string, head = 10, tail = 8): string {
  if (hex.length <= head + tail + 3) return hex
  return `${hex.slice(0, head)}…${hex.slice(-tail)}`
}

function relativeTime(ts: number): string {
  const sec = Math.floor((Date.now() - ts) / 1000)
  if (sec < 5)  return 'just now'
  if (sec < 60) return `${sec}s ago`
  if (sec < 3600) return `${Math.floor(sec / 60)}m ago`
  return `${Math.floor(sec / 3600)}h ago`
}

const TX_ICONS: Record<TxType, string> = { shield: '↓', transfer: '→', unshield: '↑' }
const TX_LABELS: Record<TxType, (r?: string) => string> = {
  shield:   () => 'Shielded',
  transfer: (r) => `Sent to ${r ?? 'unknown'}`,
  unshield: () => 'Withdrawn to public',
}

/* ─── Proof animation ─────────────────────────────────────────── */

function ProvingOverlay({ phase, progress, proofDelayMs }: {
  phase: ProvingPhase
  progress: number
  proofDelayMs: number
}) {
  const pct = Math.round(progress * 100)

  if (phase === 'generating') {
    const elapsed = Math.round((progress * proofDelayMs) / 1000)
    return (
      <div className="proving-overlay">
        <div className="proving-phases">
          <span className="phase active">Generating proof</span>
          <span className="phase-arrow">→</span>
          <span className="phase dim">Inject</span>
          <span className="phase-arrow dim">→</span>
          <span className="phase dim">Verify</span>
        </div>
        <div className="proving-title">Generating STARK proof…</div>
        <div className="proving-bar-track">
          <div className="proving-bar-fill" style={{ width: `${pct}%` }} />
        </div>
        <div className="proving-detail mono dim">
          BLAKE2s · ML-KEM-768 · WOTS+ · Stwo prover &nbsp;·&nbsp; {elapsed}s elapsed
        </div>
      </div>
    )
  }
  if (phase === 'injecting') {
    return (
      <div className="proving-overlay injecting">
        <div className="proving-phases">
          <span className="phase done">✓ Proof generated</span>
          <span className="phase-arrow">→</span>
          <span className="phase active">Inject</span>
          <span className="phase-arrow dim">→</span>
          <span className="phase dim">Verify</span>
        </div>
        <div className="proving-title">Submitting transaction to ledger…</div>
        <div className="proving-spinner" />
        <div className="proving-detail mono dim">sending proof + nullifiers + commitments</div>
      </div>
    )
  }
  if (phase === 'verifying') {
    return (
      <div className="proving-overlay verifying">
        <div className="proving-phases">
          <span className="phase done">✓ Proof generated</span>
          <span className="phase-arrow">→</span>
          <span className="phase done">✓ Injected</span>
          <span className="phase-arrow">→</span>
          <span className="phase active">Verify</span>
        </div>
        <div className="proving-title">Ledger verifying STARK proof…</div>
        <div className="proving-spinner fast" />
        <div className="proving-detail mono dim">checking nullifiers · updating Merkle tree</div>
      </div>
    )
  }
  return null
}

/* ─── Balance hero ────────────────────────────────────────────── */

function BalanceHero({ pub, priv }: { pub: number | null; priv: number }) {
  return (
    <div className="balance-hero">
      <div className="balance-card public-card">
        <div className="balance-card-icon">🌐</div>
        <div className="balance-card-label">Public balance</div>
        <div className="balance-card-amount">
          {pub === null ? <span className="dim">—</span> : <>{pub} <span className="tez-unit">ꜩ</span></>}
        </div>
        <div className="balance-card-note">{pub === null ? 'not tracked' : 'visible on-chain'}</div>
      </div>
      <div className="balance-divider">
        <div className="balance-divider-line" />
        <div className="balance-divider-icon">🔒</div>
        <div className="balance-divider-line" />
      </div>
      <div className="balance-card private-card">
        <div className="balance-card-icon">🔐</div>
        <div className="balance-card-label">Private balance</div>
        <div className="balance-card-amount">{priv} <span className="tez-unit">ꜩ</span></div>
        <div className="balance-card-note">only you can see this</div>
      </div>
    </div>
  )
}

/* ─── Action form ─────────────────────────────────────────────── */

function ActionForm({ type, maxAmount, contacts, mode, senderOptions, onConfirm, onCancel, onAddContact }: {
  type: TxType
  maxAmount?: number
  contacts: Contact[]
  mode: Mode
  senderOptions?: Record<string, number>
  onConfirm: (amount: number, alias?: string, tz1?: string) => void
  onCancel: () => void
  onAddContact: (c: Contact) => void
}) {
  const [amount, setAmount] = useState('')
  const [selectedAlias, setSelectedAlias] = useState(contacts[0]?.alias ?? '')
  const [tz1Input, setTz1Input] = useState('')
  const [showAddForm, setShowAddForm] = useState(false)
  const [newAlias, setNewAlias] = useState('')
  const [newAddress, setNewAddress] = useState('')
  const [fileError, setFileError] = useState<string | null>(null)
  const [fileName, setFileName] = useState<string | null>(null)

  const needsTz1 = mode === 'real' && (type === 'shield' || type === 'unshield')
  const parsed = parseFloat(amount)
  const validAmount = !isNaN(parsed) && parsed > 0 && (maxAmount === undefined || parsed <= maxAmount)
  const valid = validAmount
    && (type !== 'transfer' || selectedAlias !== '')
    && (!needsTz1 || /^tz[123]/.test(tz1Input.trim()))

  const titles: Record<TxType, string> = {
    shield:   '↓ Shield — public → private',
    transfer: '→ Transfer — private → recipient',
    unshield: '↑ Unshield — private → public',
  }
  const hints: Record<TxType, string> = {
    shield:   maxAmount !== undefined ? `max ${maxAmount} ꜩ (public balance)` : 'from public balance',
    transfer: maxAmount !== undefined ? `max ${maxAmount} ꜩ (private balance)` : 'from private balance',
    unshield: maxAmount !== undefined ? `max ${maxAmount} ꜩ (private balance)` : 'from private balance',
  }

  const handleFile = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0]
    if (!file) return
    setFileError(null)
    setFileName(file.name)
    const reader = new FileReader()
    reader.onload = (ev) => {
      const text = ev.target?.result as string
      try {
        const parsed = JSON.parse(text)
        const required = ['d_j', 'auth_root', 'auth_pub_seed', 'nk_tag', 'ek_v']
        const missing = required.filter(k => !(k in parsed))
        if (missing.length > 0) {
          setFileError(`Missing fields: ${missing.join(', ')}`)
          setNewAddress('')
          return
        }
        setNewAddress(text)
        if (!newAlias && file.name.endsWith('.json')) {
          setNewAlias(file.name.replace(/\.json$/, ''))
        }
      } catch {
        setFileError('Invalid JSON file')
        setNewAddress('')
      }
    }
    reader.readAsText(file)
  }

  const handleSaveContact = () => {
    if (!newAlias.trim() || !newAddress.trim()) return
    const c: Contact = { alias: newAlias.trim(), address: newAddress.trim() }
    onAddContact(c)
    setSelectedAlias(c.alias)
    setNewAlias('')
    setNewAddress('')
    setFileName(null)
    setFileError(null)
    setShowAddForm(false)
  }

  const handleConfirm = () => {
    if (!valid) return
    if (type === 'transfer') {
      onConfirm(parsed, selectedAlias, undefined)
    } else if (needsTz1) {
      onConfirm(parsed, undefined, tz1Input.trim())
    } else {
      onConfirm(parsed, undefined, undefined)
    }
  }

  return (
    <div className="action-form">
      <div className="action-form-title">{titles[type]}</div>
      {type === 'transfer' && (
        <div className="form-field">
          <label>Recipient</label>
          <div className="recipient-row">
            <select
              className="form-select"
              value={selectedAlias}
              onChange={e => setSelectedAlias(e.target.value)}
            >
              {contacts.length === 0 && (
                <option value="">— no contacts yet —</option>
              )}
              {contacts.map(c => (
                <option key={c.alias} value={c.alias}>{c.alias}</option>
              ))}
            </select>
            <button
              className="add-contact-link"
              type="button"
              onClick={() => setShowAddForm(v => !v)}
            >
              {showAddForm ? '✕ Cancel' : '+ Add contact'}
            </button>
          </div>
          {showAddForm && (
            <div className="add-contact-form">
              <div className="file-pick-area">
                <label className="file-pick-label">
                  <span className="file-pick-icon">📂</span>
                  <span>{fileName ?? 'Import address file (.json)'}</span>
                  <input
                    type="file"
                    accept=".json,application/json"
                    className="file-pick-input"
                    onChange={handleFile}
                  />
                </label>
                {fileError && <div className="file-error">{fileError}</div>}
                {newAddress && !fileError && (
                  <div className="file-ok">✓ Valid payment address</div>
                )}
              </div>
              <input
                className="form-input"
                placeholder="Contact name (e.g. Bob)"
                value={newAlias}
                onChange={e => setNewAlias(e.target.value)}
              />
              <button
                className="save-contact-btn"
                type="button"
                onClick={handleSaveContact}
                disabled={!newAlias.trim() || !newAddress.trim() || !!fileError}
              >
                Save contact
              </button>
            </div>
          )}
        </div>
      )}
      {needsTz1 && (
        <div className="form-field">
          <label>
            {type === 'shield' ? 'Your tz1 address (sender)' : 'Recipient tz1 address'}
          </label>
          <input
            className="form-input mono"
            type="text"
            list={type === 'shield' && senderOptions ? 'sender-options' : undefined}
            value={tz1Input}
            onChange={e => setTz1Input(e.target.value)}
            placeholder="tz1…"
            autoFocus
          />
          {type === 'shield' && senderOptions && (
            <datalist id="sender-options">
              {Object.entries(senderOptions).map(([addr, bal]) => (
                <option key={addr} value={addr}>{addr} — {bal} ꜩ</option>
              ))}
            </datalist>
          )}
          {type === 'shield' && senderOptions && Object.keys(senderOptions).length > 0 && (
            <div className="form-hint-list">
              Funded: {Object.entries(senderOptions).map(([addr, bal]) => (
                <button
                  key={addr}
                  type="button"
                  className="addr-chip"
                  onClick={() => setTz1Input(addr)}
                >
                  {addr} <span className="addr-chip-bal">{bal} ꜩ</span>
                </button>
              ))}
            </div>
          )}
        </div>
      )}
      <div className="form-field">
        <label>Amount <span className="form-hint">{hints[type]}</span></label>
        <div className="amount-input-row">
          <input
            className="form-input"
            type="number"
            min={0}
            max={maxAmount}
            value={amount}
            onChange={e => setAmount(e.target.value)}
            placeholder="0"
            autoFocus={!needsTz1}
          />
          <span className="amount-unit">ꜩ</span>
          {maxAmount !== undefined && (
            <button className="max-btn" onClick={() => setAmount(String(maxAmount))}>MAX</button>
          )}
        </div>
      </div>
      <div className="form-actions">
        <button className="cancel-btn" onClick={onCancel}>Cancel</button>
        <button
          className="confirm-btn"
          disabled={!valid}
          onClick={handleConfirm}
        >
          Confirm
        </button>
      </div>
    </div>
  )
}

/* ─── Transaction history ─────────────────────────────────────── */

function ProofTag({ proof }: { proof: ProofInfo | null }) {
  if (!proof) {
    return (
      <div className="proof-tag">
        <span className="proof-tag-check">✓</span>
        <span className="proof-tag-text mono dim">trust-me-bro</span>
      </div>
    )
  }
  return (
    <div className="proof-tag">
      <span className="proof-tag-check">✓</span>
      <span className="proof-tag-text mono">STARK · {proof.sizeKb} KB · {(proof.generationMs / 1000).toFixed(1)}s</span>
      <span className="pq-tag">PQ</span>
    </div>
  )
}

function TxHistory({ history }: { history: MockWalletState['history'] }) {
  const [, tick] = useState(0)
  useEffect(() => {
    const id = setInterval(() => tick(t => t + 1), 15000)
    return () => clearInterval(id)
  }, [])

  if (history.length === 0) {
    return (
      <div className="tx-history empty">
        <div className="tx-empty-state">No transactions yet</div>
      </div>
    )
  }

  return (
    <div className="tx-history">
      {history.map(tx => (
        <div key={tx.id} className="tx-row">
          <div className={`tx-icon tx-icon-${tx.type}`}>{TX_ICONS[tx.type]}</div>
          <div className="tx-body">
            <div className="tx-main">
              <span className="tx-label">{TX_LABELS[tx.type](tx.recipient)}</span>
              <span className="tx-amount">{tx.amount} ꜩ</span>
            </div>
            <ProofTag proof={tx.proof} />
          </div>
          <div className="tx-time">{relativeTime(tx.timestamp)}</div>
        </div>
      ))}
    </div>
  )
}

/* ─── Chain view (collapsible) ────────────────────────────────── */

function ChainView({ wallet }: { wallet: MockWalletState }) {
  const [open, setOpen] = useState(false)
  return (
    <div className="chain-view">
      <button className="chain-toggle" onClick={() => setOpen(o => !o)}>
        <span>What the blockchain sees</span>
        <span>{open ? '▲' : '▼'}</span>
      </button>
      {open && (
        <div className="chain-content">
          <div className="chain-note">
            An on-chain observer sees only opaque commitments — zero information about amounts, senders, or recipients.
          </div>
          <div className="chain-row">
            <span className="chain-key">Your public balance</span>
            <span className="chain-val">{wallet.publicBalance} ꜩ</span>
          </div>
          <div className="chain-row">
            <span className="chain-key">Private pool</span>
            <span className="chain-val dim">??? ꜩ</span>
          </div>
          <div className="chain-row">
            <span className="chain-key">Commitments in tree</span>
            <span className="chain-val mono">{wallet.merkleSize}</span>
          </div>
          <div className="chain-row">
            <span className="chain-key">Merkle root</span>
            <span className="chain-val mono dim">{truncateHex(wallet.merkleRoot)}</span>
          </div>
          <div className="chain-row">
            <span className="chain-key">Spent nullifiers</span>
            <span className="chain-val mono">{wallet.nullifiers.length}</span>
          </div>
          {wallet.nullifiers.slice(0, 3).map(n => (
            <div key={n} className="chain-nullifier mono dim">{truncateHex(n)}</div>
          ))}
          {wallet.nullifiers.length > 3 && (
            <div className="chain-nullifier dim">+{wallet.nullifiers.length - 3} more</div>
          )}
        </div>
      )}
    </div>
  )
}

/* ─── App ─────────────────────────────────────────────────────── */

export default function App() {
  const [mode, setMode] = useState<Mode>('mock')
  const [wallet, setWallet] = useState<MockWalletState>(INITIAL_STATE)
  const { contacts, addContact } = useAddressBook()
  const [phase, setPhase] = useState<ProvingPhase>('idle')
  const [proofProgress, setProofProgress] = useState(0)
  const [activeAction, setActiveAction] = useState<TxType | null>(null)
  const [pendingProof, setPendingProof] = useState<ProofInfo | null>(null)
  const [proofSpeed, setProofSpeed] = useState<ProofSpeed>('Fast')
  const [realState, setRealState] = useState<RealLedgerState | null>(null)
  const [realError, setRealError] = useState<string | null>(null)
  const [realPrivBalance, setRealPrivBalance] = useState<number | null>(null)
  const [realWalletError, setRealWalletError] = useState<string | null>(null)
  const [realTxHistory, setRealTxHistory] = useState<MockWalletState['history']>([])
  const [realPending, setRealPending] = useState(false)
  const [realOpError, setRealOpError] = useState<string | null>(null)
  const [myAddress, setMyAddress] = useState<Record<string, unknown> | null>(null)
  const [myAddressLoading, setMyAddressLoading] = useState(false)
  const [showReceive, setShowReceive] = useState(false)
  const rafRef = useRef<number | null>(null)
  const startRef = useRef<number>(0)
  const pendingApplyRef = useRef<(() => { state: MockWalletState; proof: ProofInfo }) | null>(null)

  const pubBalance = wallet.publicBalance
  const privBalance = privateBalance(wallet)
  const proofDelayMs = PROOF_SPEED_PRESETS.find(p => p.label === proofSpeed)!.ms
  const isBusy = phase === 'generating' || phase === 'injecting' || phase === 'verifying'

  useEffect(() => {
    if (mode !== 'real') return
    let cancelled = false

    const pollLedger = async () => {
      try {
        const s = await fetchLedgerState()
        if (!cancelled) { setRealState(s); setRealError(null) }
      } catch (e) {
        if (!cancelled) setRealError(e instanceof Error ? e.message : 'unknown error')
      }
    }

    const pollWallet = async () => {
      try {
        const bal = await getWalletBalance()
        if (!cancelled) { setRealPrivBalance(bal); setRealWalletError(null) }
      } catch (e) {
        if (!cancelled) setRealWalletError(e instanceof Error ? e.message : 'unknown error')
      }
    }

    walletScan().catch(() => {})
    pollLedger()
    pollWallet()

    const ledgerId = setInterval(pollLedger, 3000)
    const walletId = setInterval(pollWallet, 5000)
    return () => { cancelled = true; clearInterval(ledgerId); clearInterval(walletId) }
  }, [mode])

  const startProving = useCallback((applyFn: () => { state: MockWalletState; proof: ProofInfo }) => {
    pendingApplyRef.current = applyFn
    setPhase('generating')
    setProofProgress(0)
    setPendingProof(null)
    startRef.current = performance.now()

    const animate = () => {
      const progress = Math.min((performance.now() - startRef.current) / proofDelayMs, 1)
      setProofProgress(progress)
      if (progress < 1) {
        rafRef.current = requestAnimationFrame(animate)
      } else {
        setPhase('injecting')
        setTimeout(() => {
          setPhase('verifying')
          setTimeout(() => {
            const result = pendingApplyRef.current!()
            setWallet(result.state)
            setPendingProof(result.proof)
            setPhase('done')
          }, VERIFY_DELAY_MS)
        }, INJECT_DELAY_MS)
      }
    }
    rafRef.current = requestAnimationFrame(animate)
  }, [proofDelayMs])

  const handleConfirm = useCallback(async (amount: number, alias?: string, tz1?: string) => {
    if (!activeAction) return
    const action = activeAction
    setActiveAction(null)

    if (mode === 'mock') {
      startProving(() => {
        if (action === 'shield')   return applyShield(wallet, amount)
        if (action === 'transfer') return applyTransfer(wallet, amount, alias ?? 'unknown')
        return applyUnshield(wallet, amount)
      })
      return
    }

    // Real mode: call wallet-server
    setRealPending(true)
    setRealOpError(null)
    try {
      if (action === 'shield') {
        await walletShield(tz1!, amount)
      } else if (action === 'transfer') {
        const contact = contacts.find(c => c.alias === alias)
        if (!contact) throw new Error('Contact not found')
        await walletTransfer(JSON.parse(contact.address), amount)
      } else {
        await walletUnshield(tz1!, amount)
      }
      await walletScan()
      const newBal = await getWalletBalance()
      setRealPrivBalance(newBal)
      setRealTxHistory(prev => [{
        id: Math.random().toString(36).slice(2),
        type: action,
        amount,
        recipient: action === 'transfer' ? alias : undefined,
        proof: null,
        timestamp: Date.now(),
      }, ...prev])
    } catch (e) {
      setRealOpError(e instanceof Error ? e.message : 'unknown error')
    } finally {
      setRealPending(false)
    }
  }, [activeAction, mode, wallet, contacts, startProving])

  const resetWallet = () => {
    if (rafRef.current) cancelAnimationFrame(rafRef.current)
    setWallet(INITIAL_STATE)
    setPhase('idle')
    setProofProgress(0)
    setActiveAction(null)
    setPendingProof(null)
  }

  return (
    <div className="app">
      {/* Header */}
      <header className="header">
        <div className="header-left">
          <span className="logo">TzEL</span>
          <span className="logo-sub">Private Wallet</span>
        </div>
        <div className="header-right">
          {mode === 'mock' && <span className="mock-badge">MOCK MODE</span>}
          {mode === 'mock' && (
            <div className="speed-control">
              <span className="speed-label">Proof time</span>
              {PROOF_SPEED_PRESETS.map(p => (
                <button
                  key={p.label}
                  className={`speed-btn ${proofSpeed === p.label ? 'active' : ''}`}
                  onClick={() => setProofSpeed(p.label)}
                  disabled={isBusy}
                  title={`${p.ms / 1000}s`}
                >
                  {p.label}
                </button>
              ))}
            </div>
          )}
          <button
            className="mode-toggle"
            onClick={() => { setMode(m => m === 'mock' ? 'real' : 'mock'); resetWallet() }}
          >
            {mode === 'mock' ? 'Switch to Real Mode' : 'Switch to Mock Mode'}
          </button>
        </div>
      </header>

      {mode === 'mock' ? (
        <>
          {/* Balance */}
          <BalanceHero pub={pubBalance} priv={privBalance} />

          {/* Action buttons */}
          <div className="action-bar">
            {(['shield', 'transfer', 'unshield'] as TxType[]).map(type => {
              const disabled = isBusy
                || (type === 'shield'   && pubBalance === 0)
                || (type === 'transfer' && privBalance === 0)
                || (type === 'unshield' && privBalance === 0)
              return (
                <button
                  key={type}
                  className={`action-btn action-btn-${type} ${activeAction === type ? 'active' : ''}`}
                  onClick={() => setActiveAction(activeAction === type ? null : type)}
                  disabled={disabled}
                >
                  <span className="action-btn-icon">{TX_ICONS[type]}</span>
                  <span className="action-btn-label">{type.charAt(0).toUpperCase() + type.slice(1)}</span>
                </button>
              )
            })}
            <button className="reset-btn-small" onClick={resetWallet} title="Reset wallet">↺</button>
          </div>

          {/* Inline action form */}
          {activeAction && !isBusy && (
            <ActionForm
              type={activeAction}
              maxAmount={activeAction === 'shield' ? pubBalance : privBalance}
              contacts={contacts}
              mode="mock"
              senderOptions={undefined}
              onConfirm={handleConfirm}
              onCancel={() => setActiveAction(null)}
              onAddContact={addContact}
            />
          )}

          {/* Proof animation */}
          {isBusy && (
            <ProvingOverlay phase={phase} progress={proofProgress} proofDelayMs={proofDelayMs} />
          )}

          {/* Last proof banner */}
          {phase === 'done' && pendingProof && (
            <div className="proof-banner">
              <div className="proof-stat"><span className="proof-icon">✓</span><span className="proof-label">STARK proof verified</span></div>
              <div className="proof-divider" />
              <div className="proof-stat"><span className="proof-value">{pendingProof.sizeKb} KB</span><span className="proof-label">proof size</span></div>
              <div className="proof-divider" />
              <div className="proof-stat"><span className="proof-value">{(pendingProof.generationMs / 1000).toFixed(1)}s</span><span className="proof-label">generation</span></div>
              <div className="proof-divider" />
              <div className="proof-stat"><span className="proof-value">~35ms</span><span className="proof-label">verification</span></div>
              <div className="proof-divider" />
              <div className="proof-stat"><span className="pq-badge">POST-QUANTUM</span></div>
            </div>
          )}

          {/* Transaction history */}
          <div className="section-title">Transaction history</div>
          <TxHistory history={wallet.history} />

          {/* Chain view */}
          <ChainView wallet={wallet} />
        </>
      ) : (
        <>
          {/* Connection errors */}
          {(realWalletError || realError) && (
            <div className="real-conn-errors">
              {realWalletError && (
                <div className="real-conn-error">
                  <span className="conn-svc">wallet-server</span> {realWalletError}
                  <span className="conn-hint"> · run: <code>wallet-server --trust-me-bro</code></span>
                </div>
              )}
              {realError && (
                <div className="real-conn-error">
                  <span className="conn-svc">sp-ledger</span> {realError}
                  <span className="conn-hint"> · run: <code>sp-ledger --trust-me-bro</code></span>
                </div>
              )}
            </div>
          )}

          {/* Balance */}
          <BalanceHero pub={null} priv={realPrivBalance ?? 0} />

          {/* Action buttons */}
          <div className="action-bar">
            {(['shield', 'transfer', 'unshield'] as TxType[]).map(type => {
              const disabled = realPending
                || !!realWalletError
                || (type === 'transfer' && (realPrivBalance ?? 0) === 0)
                || (type === 'unshield' && (realPrivBalance ?? 0) === 0)
              return (
                <button
                  key={type}
                  className={`action-btn action-btn-${type} ${activeAction === type ? 'active' : ''}`}
                  onClick={() => setActiveAction(activeAction === type ? null : type)}
                  disabled={disabled}
                >
                  <span className="action-btn-icon">{TX_ICONS[type]}</span>
                  <span className="action-btn-label">{type.charAt(0).toUpperCase() + type.slice(1)}</span>
                </button>
              )
            })}
            <button
              className="reset-btn-small"
              onClick={async () => {
                try {
                  await walletScan()
                  const bal = await getWalletBalance()
                  setRealPrivBalance(bal)
                  setRealWalletError(null)
                } catch (e) {
                  setRealWalletError(e instanceof Error ? e.message : 'error')
                }
              }}
              title="Scan for new notes"
              disabled={realPending}
            >
              ↺
            </button>
          </div>

          {/* Receive address */}
          <div className="receive-section">
            <button
              className="receive-toggle"
              onClick={() => {
                if (!showReceive && !myAddress) {
                  setMyAddressLoading(true)
                  getWalletAddress()
                    .then(addr => { setMyAddress(addr as Record<string, unknown>); setMyAddressLoading(false) })
                    .catch(() => setMyAddressLoading(false))
                }
                setShowReceive(v => !v)
              }}
              disabled={myAddressLoading}
            >
              {myAddressLoading ? '⟳ Loading…' : (showReceive ? '▲ Hide my address' : '↙ Receive — show my address')}
            </button>
            {showReceive && myAddress && (
              <div className="receive-card">
                <div className="receive-card-preview mono">{truncateHex(JSON.stringify(myAddress), 30, 20)}</div>
                <div className="receive-card-actions">
                  <button
                    className="receive-action-btn"
                    onClick={() => navigator.clipboard.writeText(JSON.stringify(myAddress, null, 2))}
                  >
                    Copy JSON
                  </button>
                  <button
                    className="receive-action-btn"
                    onClick={() => {
                      const blob = new Blob([JSON.stringify(myAddress, null, 2)], { type: 'application/json' })
                      const url = URL.createObjectURL(blob)
                      const a = document.createElement('a')
                      a.href = url; a.download = 'my-tzel-address.json'; a.click()
                      URL.revokeObjectURL(url)
                    }}
                  >
                    Download .json
                  </button>
                  <button
                    className="receive-action-btn dim"
                    onClick={() => {
                      setMyAddressLoading(true)
                      getWalletAddress()
                        .then(addr => { setMyAddress(addr as Record<string, unknown>); setMyAddressLoading(false) })
                        .catch(() => setMyAddressLoading(false))
                    }}
                    disabled={myAddressLoading}
                  >
                    New address
                  </button>
                </div>
                <div className="receive-card-hint">Share this file with the sender — each address is single-use.</div>
              </div>
            )}
          </div>

          {/* Inline action form */}
          {activeAction && !realPending && (
            <ActionForm
              type={activeAction}
              maxAmount={activeAction !== 'shield' ? (realPrivBalance ?? 0) : undefined}
              contacts={contacts}
              mode="real"
              senderOptions={realState?.balances}
              onConfirm={handleConfirm}
              onCancel={() => setActiveAction(null)}
              onAddContact={addContact}
            />
          )}

          {/* Pending overlay */}
          {realPending && (
            <div className="proving-overlay injecting">
              <div className="proving-phases">
                <span className="phase active">Submitting</span>
                <span className="phase-arrow">→</span>
                <span className="phase dim">Scan</span>
              </div>
              <div className="proving-title">Sending transaction to ledger…</div>
              <div className="proving-spinner" />
              <div className="proving-detail mono dim">trust-me-bro · no proof generation</div>
            </div>
          )}

          {/* Op error */}
          {realOpError && (
            <div className="real-op-error">
              <span className="error-icon">✕</span> {realOpError}
              <button className="dismiss-btn" onClick={() => setRealOpError(null)}>✕</button>
            </div>
          )}

          {/* Transaction history */}
          <div className="section-title">Transaction history</div>
          <TxHistory history={realTxHistory} />

          {/* Chain view */}
          {realState && (
            <ChainView wallet={{
              publicBalance: 0,
              notes: [],
              history: [],
              merkleSize: realState.merkleSize,
              merkleRoot: realState.merkleRoot,
              nullifiers: realState.nullifiers,
            }} />
          )}
        </>
      )}
    </div>
  )
}
