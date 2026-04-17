import { useState, useCallback } from 'react'
import type { Contact } from './types'

const STORAGE_KEY = 'tzel_contacts'

const DEFAULT_CONTACTS: Contact[] = [
  { alias: 'Bob', address: 'tzel1m9f3a...(mock)' },
]

function loadContacts(): Contact[] {
  try {
    const raw = localStorage.getItem(STORAGE_KEY)
    if (raw) {
      const parsed = JSON.parse(raw) as Contact[]
      if (Array.isArray(parsed) && parsed.length > 0) return parsed
    }
  } catch {
    // ignore parse errors
  }
  return DEFAULT_CONTACTS
}

function saveContacts(contacts: Contact[]): void {
  localStorage.setItem(STORAGE_KEY, JSON.stringify(contacts))
}

export function useAddressBook() {
  const [contacts, setContacts] = useState<Contact[]>(loadContacts)

  const addContact = useCallback((c: Contact) => {
    setContacts(prev => {
      const next = [...prev.filter(x => x.alias !== c.alias), c]
      saveContacts(next)
      return next
    })
  }, [])

  const removeContact = useCallback((alias: string) => {
    setContacts(prev => {
      const next = prev.filter(x => x.alias !== alias)
      saveContacts(next)
      return next
    })
  }, [])

  return { contacts, addContact, removeContact }
}
