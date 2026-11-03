const el = id => document.getElementById(id)
let pending = false
function text(tag, value) {
  const element = document.createElement(tag)
  element.textContent = value
  return element
}
function render(data) {
  el('state').textContent = `${data.running ? 'Test läuft' : 'Bereit / Test beendet'} · tatsächlich Ø ${data.achieved_rate || 0} Req/s · ${data.inflight || 0} gleichzeitig · ${data.elapsed_seconds || 0}s`
  el('start').disabled = pending || data.running
  el('stop').disabled = pending || !data.running
  el('stats').replaceChildren(...data.targets.map(node => {
    const stat = data.stats[node] || { count: 0, status: {}, latency_avg: 0, latency_max: 0 }
    const card = document.createElement('section')
    card.append(text('h2', node), text('strong', `${stat.count} Requests`), text('p', `Ø ${stat.latency_avg} ms · Max ${stat.latency_max} ms`), text('p', Object.entries(stat.status).map(([status, count]) => `${status}: ${count}`).join(' · ') || 'Noch keine Requests'))
    return card
  }))
  el('log').replaceChildren(...data.log.map(item => {
    const row = document.createElement('tr')
    for (const value of [item.time, item.node, item.path, item.status, `${item.latency_ms} ms`]) row.append(text('td', value))
    return row
  }))
}
async function request(path, data) {
  const response = await fetch(path, data ? { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(data) } : {})
  const result = await response.json()
  if (!response.ok) throw new Error(result.error || 'Anfrage fehlgeschlagen')
  return result
}
async function command(path, data) {
  pending = true
  el('start').disabled = true
  el('stop').disabled = true
  el('error').textContent = ''
  try { render(await request(path, data)) }
  catch (error) { el('error').textContent = error.message }
  finally { pending = false; await poll() }
}
el('controls').addEventListener('submit', event => {
  event.preventDefault()
  command('/start', { concurrency: Number(el('concurrency').value), target: el('target').value, profile: el('profile').value, rate: Number(el('rate').value), duration: Number(el('duration').value) })
})
el('stop').addEventListener('click', () => command('/stop', {}))
async function poll() {
  try { render(await request('/status')) }
  catch (error) { el('state').textContent = 'Status nicht erreichbar'; el('error').textContent = error.message }
}
async function loop() {
  if (!pending) await poll()
  setTimeout(loop, 1000)
}
loop()
