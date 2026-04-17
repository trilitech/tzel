import type { MockWalletState, Note, TxRecord, ProofInfo } from './types'

export const INJECT_DELAY_MS = 1200
export const VERIFY_DELAY_MS = 600

export const PROOF_SPEED_PRESETS = [
  { label: 'Fast',      ms: 2000  },
  { label: 'Normal',    ms: 10000 },
  { label: 'Realistic', ms: 30000 },
] as const

export type ProofSpeed = typeof PROOF_SPEED_PRESETS[number]['label']

function randomHex(): string {
  return '0x' + Array.from({ length: 64 }, () => Math.floor(Math.random() * 16).toString(16)).join('')
}

function randomProof(): ProofInfo {
  return {
    sizeKb: 300 + Math.floor(Math.random() * 20),
    generationMs: 2500 + Math.floor(Math.random() * 800),
  }
}

export const INITIAL_STATE: MockWalletState = {
  publicBalance: 200,
  notes: [],
  history: [],
  merkleSize: 0,
  merkleRoot: '0x' + '0'.repeat(64),
  nullifiers: [],
}

export function privateBalance(state: MockWalletState): number {
  return state.notes.filter(n => !n.spent).reduce((sum, n) => sum + n.amount, 0)
}

export function applyShield(state: MockWalletState, amount: number): { state: MockWalletState; proof: ProofInfo } {
  const proof = randomProof()
  const noteIndex = state.merkleSize
  const note: Note = { id: `note_${noteIndex}`, amount, merkleIndex: noteIndex, spent: false }
  const tx: TxRecord = { id: `tx_${Date.now()}`, type: 'shield', amount, proof, timestamp: Date.now() }
  return {
    proof,
    state: {
      ...state,
      publicBalance: state.publicBalance - amount,
      notes: [...state.notes, note],
      history: [tx, ...state.history],
      merkleSize: state.merkleSize + 1,
      merkleRoot: randomHex(),
    },
  }
}

export function applyTransfer(state: MockWalletState, amount: number, recipient: string): { state: MockWalletState; proof: ProofInfo } {
  const proof = randomProof()
  const source = state.notes.find(n => !n.spent && n.amount >= amount)
    ?? state.notes.filter(n => !n.spent).sort((a, b) => b.amount - a.amount)[0]
  if (!source) throw new Error('No active note')

  const change = source.amount - amount
  const updatedNotes = state.notes.map(n => n.id === source.id ? { ...n, spent: true } : n)
  const changeNote: Note | null = change > 0
    ? { id: `note_${state.merkleSize + 1}`, amount: change, merkleIndex: state.merkleSize + 1, spent: false }
    : null
  const tx: TxRecord = { id: `tx_${Date.now()}`, type: 'transfer', amount, recipient, proof, timestamp: Date.now() }

  return {
    proof,
    state: {
      ...state,
      notes: changeNote ? [...updatedNotes, changeNote] : updatedNotes,
      history: [tx, ...state.history],
      merkleSize: state.merkleSize + (change > 0 ? 2 : 1),
      merkleRoot: randomHex(),
      nullifiers: [...state.nullifiers, randomHex()],
    },
  }
}

export function applyUnshield(state: MockWalletState, amount: number): { state: MockWalletState; proof: ProofInfo } {
  const proof = randomProof()
  const source = state.notes.find(n => !n.spent && n.amount >= amount)
    ?? state.notes.filter(n => !n.spent).sort((a, b) => b.amount - a.amount)[0]
  if (!source) throw new Error('No active note')

  const change = source.amount - amount
  const updatedNotes = state.notes.map(n => n.id === source.id ? { ...n, spent: true } : n)
  const changeNote: Note | null = change > 0
    ? { id: `note_${state.merkleSize}`, amount: change, merkleIndex: state.merkleSize, spent: false }
    : null
  const tx: TxRecord = { id: `tx_${Date.now()}`, type: 'unshield', amount, proof, timestamp: Date.now() }

  return {
    proof,
    state: {
      ...state,
      publicBalance: state.publicBalance + amount,
      notes: changeNote ? [...updatedNotes, changeNote] : updatedNotes,
      history: [tx, ...state.history],
      merkleSize: state.merkleSize + (change > 0 ? 1 : 0),
      merkleRoot: randomHex(),
      nullifiers: [...state.nullifiers, randomHex()],
    },
  }
}
