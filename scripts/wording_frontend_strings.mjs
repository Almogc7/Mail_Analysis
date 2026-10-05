// Extracts the user-visible string candidates of the frontend source for scripts/check_wording.py.
//
//   node scripts/wording_frontend_strings.mjs [SRC_DIR]      prints JSON: {"strings": [...], "exempt_tokens": [...]}
//
// It uses the TypeScript compiler API that the frontend already depends on, so comments are skipped by the parser itself and JSX text, JSX attribute
// strings and string literals are told apart reliably. Test files and the test/ helper folder are not scanned.
//
// What is user-visible: JSX text; the strings of the attributes title, aria-label, aria-description, placeholder, alt and label; console messages; and
// any other string literal that reads as prose (whitespace plus at least two words). What is NOT: className, key, id, type, role and similar attributes,
// strings in type positions (unions, literal types), module specifiers, property names, and single-word strings (internal keys and tokens such as the
// frozen v1 value 'benign'). A single-word string that IS a banned word is listed under exempt_tokens, so the exemption is visible, never silent.
import { createRequire } from 'node:module'
import fs from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'

const here = path.dirname(fileURLToPath(import.meta.url))
const root = path.resolve(here, '..')
const require = createRequire(path.join(root, 'frontend', 'package.json'))
const ts = require('typescript')
const srcDir = path.resolve(process.argv[2] ?? path.join(root, 'frontend', 'src'))

const SKIP_ATTRS = new Set([
  'className', 'key', 'id', 'htmlFor', 'type', 'role', 'name', 'href', 'src', 'rel', 'target', 'style', 'value', 'width', 'height',
  'viewBox', 'd', 'fill', 'stroke', 'xmlns', 'data-testid', 'accept', 'autoComplete', 'inputMode', 'lang', 'dir', 'tabIndex',
])
const TEXT_ATTRS = new Set(['title', 'aria-label', 'aria-description', 'aria-roledescription', 'placeholder', 'alt', 'label'])
const BANNED = /(?<![A-Za-z0-9_])(safe|clean|legit|benign|harmless)(?![A-Za-z0-9_])/i

function* walk(dir) {
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    const full = path.join(dir, entry.name)
    if (entry.isDirectory()) {
      if (entry.name === 'test' || entry.name === 'node_modules') continue
      yield* walk(full)
    } else if (/\.(ts|tsx)$/.test(entry.name) && !/\.test\.(ts|tsx)$/.test(entry.name) && !entry.name.endsWith('.d.ts')) {
      yield full
    }
  }
}

const isProse = (text) => /\s/.test(text.trim()) && (text.match(/[A-Za-z]{2,}/g) ?? []).length >= 2

function inTypePosition(node) {
  for (let p = node.parent; p; p = p.parent) if (ts.isTypeNode(p)) return true
  return false
}

function nearestAttribute(node) {
  for (let p = node.parent; p; p = p.parent) {
    if (ts.isJsxAttribute(p)) return p
    if (ts.isJsxElement(p) || ts.isJsxFragment(p) || ts.isSourceFile(p)) return null
  }
  return null
}

function consoleCall(node) {
  for (let p = node.parent; p; p = p.parent) {
    if (ts.isCallExpression(p) && p.expression.getText().startsWith('console.')) return true
    if (ts.isSourceFile(p)) return false
  }
  return false
}

const strings = []
const exemptTokens = []

for (const file of walk(srcDir)) {
  const text = fs.readFileSync(file, 'utf8')
  const sf = ts.createSourceFile(file, text, ts.ScriptTarget.Latest, true, file.endsWith('.tsx') ? ts.ScriptKind.TSX : ts.ScriptKind.TS)
  const rel = path.relative(root, file).split(path.sep).join('/')
  const lineOf = (node) => sf.getLineAndCharacterOfPosition(node.getStart(sf)).line + 1
  const add = (node, kind, value) => strings.push({ file: rel, line: lineOf(node), kind, text: value.replace(/\s+/g, ' ').trim() })

  const visit = (node) => {
    if (ts.isImportDeclaration(node) || ts.isExportDeclaration(node)) return
    if (ts.isJsxText(node)) {
      const value = node.text.replace(/\s+/g, ' ').trim()
      if (value) add(node, 'jsx text', value)
    } else if (ts.isStringLiteral(node) || ts.isNoSubstitutionTemplateLiteral(node) || ts.isTemplateHead(node) || ts.isTemplateMiddle(node) || ts.isTemplateTail(node)) {
      const value = node.text
      const parent = node.parent
      const isPropertyName = (ts.isPropertyAssignment(parent) || ts.isPropertySignature(parent) || ts.isEnumMember(parent)) && parent.name === node
      if (!inTypePosition(node) && !isPropertyName && value.trim()) {
        const attr = nearestAttribute(node)
        const attrName = attr ? attr.name.getText() : null
        if (attrName && SKIP_ATTRS.has(attrName)) {
          // className, key, type ... : not user-visible
        } else if (attrName && TEXT_ATTRS.has(attrName)) {
          add(node, `attribute ${attrName}`, value)
        } else if (consoleCall(node)) {
          add(node, 'log message', value)
        } else if (isProse(value)) {
          add(node, 'string literal', value)
        } else if (BANNED.test(value) && !/\s/.test(value.trim())) {
          exemptTokens.push({ file: rel, line: lineOf(node), kind: 'single-word token', text: value })
        }
      }
    }
    ts.forEachChild(node, visit)
  }
  visit(sf)
}

process.stdout.write(JSON.stringify({ strings, exempt_tokens: exemptTokens }))
