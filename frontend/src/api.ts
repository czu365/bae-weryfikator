export let csrf='';
export function setCsrf(value:string){csrf=value}
export async function api(path:string,method='GET',body?:unknown):Promise<any>{
  const response=await fetch('/api'+path,{method,credentials:'same-origin',headers:{...(method!=='GET'?{'X-CSRF-Token':csrf}:{}),...(body&&!(body instanceof FormData)?{'Content-Type':'application/json'}:{})},body:body instanceof FormData?body:body?JSON.stringify(body):undefined});
  if(!response.ok){let e;try{e=await response.json()}catch{e={detail:'Serwer nie odpowiedział poprawnie'}}const detail=typeof e.detail==='string'?e.detail:'Nieprawidłowe żądanie';const reference=typeof e.reference==='string'&&/^[a-f0-9]{16}$/.test(e.reference)?' · ID błędu: '+e.reference:'';throw new Error(detail+' (HTTP '+response.status+')'+reference)}
  return response.json();
}
export async function download(path:string,body:any){
  const r=await fetch('/api'+path,{method:'POST',credentials:'same-origin',headers:{'Content-Type':'application/json','X-CSRF-Token':csrf},body:JSON.stringify(body)});
  if(!r.ok){const e=await r.json();throw new Error(e.detail||'Błąd eksportu')}
  const blob=await r.blob(),url=URL.createObjectURL(blob),a=document.createElement('a');a.href=url;a.download=r.headers.get('Content-Disposition')?.match(/filename="([^"]+)"/)?.[1]||'wyniki';a.click();setTimeout(()=>URL.revokeObjectURL(url),1000);
}
