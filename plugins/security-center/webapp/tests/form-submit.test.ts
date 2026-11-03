import { readdirSync, readFileSync } from 'node:fs'
import { runInNewContext } from 'node:vm'
import { expect, test } from 'bun:test'

test('model-less security forms bind the submit event actually emitted by Antdv', () => {
  const library = readFileSync(new URL('../node_modules/antdv-next/dist/form/Form.js', import.meta.url), 'utf8')
  const body = library.match(/function handleSubmit\(e\) \{([\s\S]*?)\n\t\}/)?.[1]
  expect(typeof body).toBe('string')
  const emitted: string[] = []
  let prevented = false
  runInNewContext(`(function(e) {${body}})(event)`, {
    event: {
      preventDefault: () => { prevented = true },
      stopPropagation: () => {},
    },
    props: {},
    emit: (name: string) => emitted.push(name),
    validateFields: () => { throw new Error('Model-less form must not use model validation') },
  })
  expect(prevented).toBe(true)
  expect(emitted).toEqual(['submit'])

  const handlers: string[] = []
  const views = new URL('../src/views/', import.meta.url)
  for (const file of readdirSync(views).filter(name => name.endsWith('.vue'))) {
    const source = readFileSync(new URL(file, views), 'utf8')
    for (const match of source.matchAll(/<AForm\b[^>]*>/g)) {
      const tag = match[0]
      if (tag.includes('@finish='))
        expect(tag.includes(':model=') || tag.includes(' model=')).toBe(true)
      const handler = tag.match(/@submit="([^"]+)"/)?.[1]
      if (handler)
        handlers.push(handler)
    }
  }
  expect(handlers.sort()).toEqual(['addBan', 'apply', 'saveWaf'])
})
