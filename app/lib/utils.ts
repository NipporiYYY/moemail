import { type ClassValue, clsx } from "clsx"
import { twMerge } from "tailwind-merge"

export function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs))
}

const PBKDF2_ITERATIONS = 100_000
const SALT_LENGTH = 16
const HASH_LENGTH = 32

export async function hashPassword(password: string): Promise<string> {
  const encoder = new TextEncoder()
  const salt = crypto.getRandomValues(new Uint8Array(SALT_LENGTH))
  const keyMaterial = await crypto.subtle.importKey(
    "raw",
    encoder.encode(password),
    "PBKDF2",
    false,
    ["deriveBits"]
  )
  const hash = await crypto.subtle.deriveBits(
    { name: "PBKDF2", salt, iterations: PBKDF2_ITERATIONS, hash: "SHA-256" },
    keyMaterial,
    HASH_LENGTH * 8
  )
  const saltB64 = btoa(String.fromCharCode(...salt))
  const hashB64 = btoa(String.fromCharCode(...new Uint8Array(hash)))
  return `${saltB64}:${hashB64}`
}

async function hashPasswordLegacy(password: string): Promise<string> {
  const encoder = new TextEncoder()
  const salt = process.env.AUTH_SECRET || ''
  const data = encoder.encode(password + salt)
  const hash = await crypto.subtle.digest('SHA-256', data)
  return btoa(String.fromCharCode(...new Uint8Array(hash)))
}

export async function comparePassword(password: string, hashedPassword: string): Promise<boolean> {
  if (!hashedPassword.includes(':')) {
    return await hashPasswordLegacy(password) === hashedPassword
  }
  const [saltB64, expectedHashB64] = hashedPassword.split(':')
  const encoder = new TextEncoder()
  const salt = Uint8Array.from(atob(saltB64), c => c.charCodeAt(0))
  const keyMaterial = await crypto.subtle.importKey(
    "raw",
    encoder.encode(password),
    "PBKDF2",
    false,
    ["deriveBits"]
  )
  const hash = await crypto.subtle.deriveBits(
    { name: "PBKDF2", salt, iterations: PBKDF2_ITERATIONS, hash: "SHA-256" },
    keyMaterial,
    HASH_LENGTH * 8
  )
  const hashB64 = btoa(String.fromCharCode(...new Uint8Array(hash)))
  return hashB64 === expectedHashB64
}