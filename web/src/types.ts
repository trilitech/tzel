export interface Note {
  id: string
  amount: number
  merkleIndex: number
  spent: boolean
}

export interface ProofInfo {
  sizeKb: number
  generationMs: number
}

export type TxType = 'shield' | 'transfer' | 'unshield'

export interface TxRecord {
  id: string
  type: TxType
  amount: number
  recipient?: string
  proof: ProofInfo | null
  timestamp: number
}

export interface MockWalletState {
  publicBalance: number
  notes: Note[]
  history: TxRecord[]
  merkleSize: number
  merkleRoot: string
  nullifiers: string[]
}

export interface Contact {
  alias: string
  address: string
}
