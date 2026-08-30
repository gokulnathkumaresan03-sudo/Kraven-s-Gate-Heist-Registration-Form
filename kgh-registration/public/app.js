const form = document.getElementById('registrationForm');
const msg = document.getElementById('formMessage');
const overlay = document.getElementById('successOverlay');
const teamIdEl = document.getElementById('teamId');
const closeSuccess = document.getElementById('closeSuccess');

function setMessage(text, ok=false){ msg.textContent=text; msg.style.color=ok?'#36df8a':'#ff6f91'; }

form.addEventListener('submit', async (e) => {
  e.preventDefault();
  setMessage('');
  if (!form.reportValidity()) return;
  const data = Object.fromEntries(new FormData(form).entries());
  data.consent = form.elements.consent.checked;
  const button = form.querySelector('button[type="submit"]');
  button.disabled = true;
  button.querySelector('span').textContent = 'SECURING YOUR GATE...';
  try {
    const res = await fetch('/api/register', {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify(data)});
    const result = await res.json();
    if (!res.ok) throw new Error(result.error || 'Registration failed');
    teamIdEl.textContent = result.teamId;
    overlay.classList.add('open');
    overlay.setAttribute('aria-hidden','false');
    form.reset();
  } catch (err) {
    setMessage(err.message || 'Something went wrong. Please try again.');
  } finally {
    button.disabled = false;
    button.querySelector('span').textContent = 'SUBMIT REGISTRATION — ENTER THE HEIST';
  }
});

closeSuccess.addEventListener('click', () => {
  overlay.classList.remove('open');
  overlay.setAttribute('aria-hidden','true');
  document.getElementById('register').scrollIntoView({behavior:'smooth'});
});

overlay.addEventListener('click', e => { if(e.target === overlay) closeSuccess.click(); });
