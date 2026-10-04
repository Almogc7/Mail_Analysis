/// <reference types="node" />
import { readdirSync, readFileSync } from 'node:fs'
import { resolve } from 'node:path'

// vitest turns every imported .css into an empty string (even with ?raw), so tests that must look at stylesheet text read it from disk.
// import.meta.url is not a file URL under jsdom, so this relies on vitest running from the frontend folder (npm test does).
const SRC = resolve(process.cwd(), 'src') + '/'

export function readSrc(relative: string): string {
  return readFileSync(`${SRC}${relative}`, 'utf8')
}

export function listSrc(extension: string): string[] {
  return (readdirSync(SRC, { recursive: true }) as string[]).map((p) => p.replaceAll('\\', '/')).filter((p) => p.endsWith(extension))
}
