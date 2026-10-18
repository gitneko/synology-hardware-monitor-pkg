export function downloadFile(content,name,type) {
  const url=URL.createObjectURL(new Blob([content],{type}));
  const anchor=document.createElement('a');anchor.href=url;anchor.download=name;document.body.append(anchor);anchor.click();anchor.remove();
  setTimeout(()=>URL.revokeObjectURL(url),30000);
}
export function downloadName(extension){return `HardwareMonitor-${new Date().toISOString().replace(/[:.]/g,'-')}.${extension}`;}
