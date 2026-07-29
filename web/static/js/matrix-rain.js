// Matrix rain canvas background effect, shared across index/loading/report pages.
// Expects a <canvas id="matrix-rain"> element to already be on the page.
(function () {
  const canvas = document.getElementById('matrix-rain');
  if (!canvas) return;
  const ctx = canvas.getContext('2d');
  const chars = '01アイウエオカキクサシスタチツナニヌハヒフマミムラリル';
  let cols, drops;

  function resize() {
    canvas.width  = window.innerWidth;
    canvas.height = window.innerHeight;
    cols  = Math.floor(canvas.width / 18);
    drops = Array(cols).fill(1);
  }
  resize();
  window.addEventListener('resize', resize);

  setInterval(() => {
    ctx.fillStyle = 'rgba(0,0,0,0.04)';
    ctx.fillRect(0, 0, canvas.width, canvas.height);
    ctx.font = '13px Monaco, Courier New, monospace';
    for (let i = 0; i < drops.length; i++) {
      ctx.fillStyle = Math.random() > 0.6 ? '#8b001e' : '#cc0033';
      const ch = chars[Math.floor(Math.random() * chars.length)];
      ctx.fillText(ch, i * 18, drops[i] * 18);
      if (drops[i] * 18 > canvas.height && Math.random() > 0.975) drops[i] = 0;
      drops[i]++;
    }
  }, 90);
})();
