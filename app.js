const form=document.getElementById('loginForm');
const msg=document.getElementById('msg');
form.addEventListener('submit',async(e)=>{e.preventDefault();msg.textContent='Backend Cloudflare belum dikonfigurasi. Setelah Worker + D1 dibuat, form ini akan terhubung ke sistem login.';});