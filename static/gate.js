'use strict';
const download = document.getElementById('download');
if (download) download.addEventListener('click', () => {
  const text = `Access Gate — ${download.dataset.name}\nValid: ${download.dataset.start} to ${download.dataset.end} (Europe/Amsterdam)\nSingle use, ${download.dataset.duration} of access per code.\n\n${document.getElementById('codes').value}\n`;
  const url = URL.createObjectURL(new Blob([text], {type:'text/plain;charset=utf-8'}));
  const a = document.createElement('a'); a.href = url; a.download = `access-codes-${download.dataset.id}.txt`; a.click();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
});
const batchForm = document.getElementById('batch-form');
if (batchForm) {
  const label = (value,unit) => `${value} ${Number(value) === 1 ? unit.slice(0,-1) : unit}`;
  const preview = () => { const f = new FormData(batchForm); document.getElementById('batch-summary').textContent = `${f.get('count')} single-use codes, valid for ${label(f.get('validity_value'),f.get('validity_unit'))} from generation. Each code grants ${label(f.get('access_value'),f.get('access_unit'))} from activation.`; };
  batchForm.addEventListener('input',preview); preview();
}
const extendForm = document.getElementById('extend-form');
if (extendForm) {
  const preview = () => {
    const f = new FormData(extendForm), value = Number(f.get('value'));
    const end = (Number(extendForm.dataset.expires) + value * (f.get('unit') === 'hours' ? 3600 : 60))*1000;
    const maximum = f.get('unit') === 'hours' ? 168 : 10080;
    document.getElementById('extension-preview').textContent = Number.isFinite(end) && Number.isInteger(value) && value > 0 && value <= maximum ? `New end time: ${new Intl.DateTimeFormat('en-GB',{timeZone:'Europe/Amsterdam',dateStyle:'medium',timeStyle:'medium'}).format(end)} (Europe/Amsterdam)` : 'Enter a positive whole duration of at most 7 days.';
  };
  extendForm.addEventListener('input',preview); preview();
}
const countdown = document.getElementById('access-countdown');
if (countdown) {
  let expiry = Number(countdown.dataset.expires), offset = 0;
  const tick = () => {
    const left = Math.max(0,Math.ceil(expiry-Date.now()/1000-offset));
    countdown.textContent = left ? `Time remaining: ${Math.floor(left/3600)}h ${Math.floor(left%3600/60)}m ${left%60}s` : 'Access expired. Refresh this page to enter another unused code.';
  };
  const sync = async () => { try { const response = await fetch('/status',{cache:'no-store'}); if (!response.ok) return; const state = await response.json(); offset = state.server_time-Date.now()/1000; expiry = state.active ? state.expires : 0; tick(); } catch (_) { /* Server-side checks remain authoritative. */ } };
  tick(); sync(); setInterval(tick,1000); setInterval(sync,5000);
}

const domainForm = document.getElementById('domain-form');
if (domainForm) {
  const preview = () => {
    const data = new FormData(domainForm), domain = String(data.get('domain') || 'example.org').trim();
    document.getElementById('domain-preview').textContent = data.get('enabled') ? (data.get('subdomains') ? `Matches ${domain} and its subdomains, such as www.${domain}. Other domains stay unaffected.` : `Matches ${domain} only. Subdomains stay unaffected.`) : 'Disabled rule: this entry will not restrict any domain.';
  };
  domainForm.addEventListener('input',preview); preview();
}
