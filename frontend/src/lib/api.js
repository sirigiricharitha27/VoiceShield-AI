const BASE = import.meta.env.VITE_API_URL || 'http://127.0.0.1:5000/api';
export const getToken = () => localStorage.getItem('vs_token');
export const setToken = t => t ? localStorage.setItem('vs_token', t) : localStorage.removeItem('vs_token');
export async function api(path, options={}) {
  const headers = new Headers(options.headers || {});
  if (getToken()) headers.set('Authorization', `Bearer ${getToken()}`);
  if (options.body && !(options.body instanceof FormData)) headers.set('Content-Type','application/json');
  const res = await fetch(`${BASE}${path}`, {...options, headers});
  const type = res.headers.get('content-type') || '';
  const data = type.includes('application/json') ? await res.json() : await res.blob();
  if (!res.ok) throw new Error(data?.error || `Request failed (${res.status})`);
  return data;
}
export const json = (method, body) => ({method, body:JSON.stringify(body)});
export const download = async (path, filename) => {
  const headers = {}; if(getToken()) headers.Authorization=`Bearer ${getToken()}`;
  const res=await fetch(`${BASE}${path}`,{headers}); if(!res.ok){let d={};try{d=await res.json()}catch{};throw new Error(d.error||'Download failed')}
  const blob=await res.blob(); const url=URL.createObjectURL(blob); const a=document.createElement('a');a.href=url;a.download=filename;document.body.appendChild(a);a.click();a.remove();URL.revokeObjectURL(url);
};
