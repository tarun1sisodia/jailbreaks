// Guard the performance contract: routes must stay lazy and keep page CSS out
// of the initial shell. Vite's manifest reflects the actual production graph.
import assert from 'node:assert/strict'
import { readFile, stat } from 'node:fs/promises'
import { basename, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'

const dist = fileURLToPath(new URL('../dist/', import.meta.url))
const manifest = JSON.parse(await readFile(resolve(dist, '.vite/manifest.json'), 'utf8'))
const entry = manifest['index.html']
const pages = ['Dashboard', 'Scans', 'NewScan', 'Console', 'Report', 'Catalog', 'Settings', 'NotFound']
assert.ok(entry?.isEntry, 'Missing Vite entry in the production manifest')

const eager = new Set()
function visitStatic(key) {
  if (eager.has(key)) return
  eager.add(key)
  for (const imported of manifest[key]?.imports || []) visitStatic(imported)
}
visitStatic('index.html')
const entryCss = new Set(entry.css || [])

for (const name of pages) {
  const key = `src/pages/${name}.tsx`
  const chunk = manifest[key]
  assert.ok(chunk?.isDynamicEntry, `${name} is not a dynamic entry`)
  assert.ok(entry.dynamicImports?.includes(key), `${name} is not a lazy route`)
  assert.ok(!eager.has(key), `${name} is included in the initial JavaScript graph`)
  await stat(resolve(dist, chunk.file))
  if (name !== 'NotFound') {
    const ownCss = chunk.css?.find((file) => basename(file).startsWith(`${name}-`))
    assert.ok(ownCss, `${name} has no page-specific CSS chunk`)
    assert.ok(!entryCss.has(ownCss), `${name} CSS is eagerly bundled`)
    for (const css of chunk.css) await stat(resolve(dist, css))
  }
}
console.log(`Verified ${pages.length} lazy routes and ${pages.length - 1} page CSS chunks.`)
