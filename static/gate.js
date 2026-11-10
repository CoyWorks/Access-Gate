'use strict';
const download = document.getElementById('download');
if (download) download.addEventListener('click', () => {
  const text = `Access Gate — week starting ${download.dataset.week}\nSingle use, 15 minutes of access per code.\n\n${document.getElementById('codes').value}\n`;
  const url = URL.createObjectURL(new Blob([text], {type:'text/plain;charset=utf-8'}));
  const a = document.createElement('a'); a.href = url; a.download = `access-codes-${download.dataset.week}.txt`; a.click();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
});
