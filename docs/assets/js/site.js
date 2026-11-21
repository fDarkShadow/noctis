/* noctis site — progressive enhancement only; every page works without JS. */
(function () {
  'use strict';

  function flash(btn, text) {
    var o = btn.textContent;
    btn.textContent = text;
    setTimeout(function () { btn.textContent = o; }, 1400);
  }
  function copy(text, btn) {
    if (!navigator.clipboard) return;
    navigator.clipboard.writeText(text).then(function () { flash(btn, 'Copied'); });
  }

  // 1. explicit copy buttons (landing `docker pull` line)
  document.querySelectorAll('[data-copy]').forEach(function (b) {
    b.addEventListener('click', function () { copy(b.getAttribute('data-copy'), b); });
  });

  // 2. code blocks: keyboard-scrollable + a copy button on rendered markdown code
  document.querySelectorAll('pre').forEach(function (pre) {
    if (!pre.hasAttribute('tabindex')) pre.setAttribute('tabindex', '0');
  });
  document.querySelectorAll('.prose div.highlighter-rouge').forEach(function (box) {
    var code = box.querySelector('code');
    if (!code) return;
    var b = document.createElement('button');
    b.type = 'button';
    b.className = 'code-copy';
    b.textContent = 'Copy';
    b.addEventListener('click', function () { copy(code.innerText.replace(/\n$/, ''), b); });
    box.appendChild(b);
  });

  // 3. heading anchors + "On this page"
  var prose = document.querySelector('.prose');
  if (prose) {
    var heads = prose.querySelectorAll('h2[id], h3[id]');
    var labels = new Map();
    heads.forEach(function (h) { labels.set(h, h.textContent.trim()); });
    heads.forEach(function (h) {
      var a = document.createElement('a');
      a.className = 'anchor';
      a.href = '#' + h.id;
      a.setAttribute('aria-label', 'Link to this section');
      a.textContent = '#';
      h.appendChild(a);
    });
    if (heads.length >= 2) {
      document.querySelectorAll('.toc-list').forEach(function (list) {
        var ul = document.createElement('ul');
        heads.forEach(function (h) {
          var li = document.createElement('li');
          li.className = h.tagName === 'H3' ? 'sub' : '';
          var a = document.createElement('a');
          a.href = '#' + h.id;
          a.textContent = labels.get(h);
          li.appendChild(a);
          ul.appendChild(li);
        });
        list.appendChild(ul);
      });
      document.querySelectorAll('.toc, .toc-inline').forEach(function (el) { el.hidden = false; });

      // highlight the section currently in view
      var links = document.querySelectorAll('.toc .toc-list a');
      if ('IntersectionObserver' in window && links.length) {
        var byId = {};
        links.forEach(function (a) { byId[a.getAttribute('href').slice(1)] = a; });
        var io = new IntersectionObserver(function (entries) {
          entries.forEach(function (e) {
            if (e.isIntersecting && byId[e.target.id]) {
              links.forEach(function (a) { a.classList.remove('active'); });
              byId[e.target.id].classList.add('active');
            }
          });
        }, { rootMargin: '-80px 0px -70% 0px' });
        heads.forEach(function (h) { io.observe(h); });
      }
    }
  }

  // 4. (the docs menu is collapsed on small screens by an inline script in doc.html,
  //     before first paint, so it never shifts the layout)

  // 5. search — fetch the doc pages on first use, then filter client-side
  var input = document.getElementById('doc-search');
  var out = document.getElementById('search-results');
  if (input && out) {
    var index = null;
    var loading = null;
    function load() {
      if (loading) return loading;
      var links = Array.prototype.slice.call(document.querySelectorAll('.side-menu a'));
      loading = Promise.all(links.map(function (a) {
        return fetch(a.href).then(function (r) { return r.text(); }).then(function (html) {
          var doc = new DOMParser().parseFromString(html, 'text/html');
          var body = doc.querySelector('.prose') || doc.querySelector('main');
          return { title: a.textContent.trim(), url: a.href, text: body ? body.textContent.replace(/\s+/g, ' ') : '' };
        }).catch(function () { return null; });
      })).then(function (pages) { index = pages.filter(Boolean); return index; });
      return loading;
    }
    function esc(s) { return s.replace(/[&<>"]/g, function (c) { return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c]; }); }
    function render(q) {
      if (!q) { out.hidden = true; out.innerHTML = ''; return; }
      var ql = q.toLowerCase();
      var hits = index.map(function (p) {
        var t = p.title.toLowerCase().indexOf(ql);
        var i = p.text.toLowerCase().indexOf(ql);
        if (t < 0 && i < 0) return null;
        var snip = i >= 0 ? p.text.slice(Math.max(0, i - 40), i + q.length + 60) : p.text.slice(0, 100);
        return { p: p, score: t >= 0 ? 0 : 1, snip: snip };
      }).filter(Boolean).sort(function (a, b) { return a.score - b.score; });
      if (!hits.length) { out.innerHTML = '<p class="sr-none">No results for “' + esc(q) + '”.</p>'; out.hidden = false; return; }
      var re = new RegExp('(' + q.replace(/[.*+?^${}()|[\]\\]/g, '\\$&') + ')', 'ig');
      out.innerHTML = hits.map(function (h) {
        return '<a href="' + h.p.url + '"><b>' + esc(h.p.title) + '</b><span>…' +
          esc(h.snip).replace(re, '<mark>$1</mark>') + '…</span></a>';
      }).join('');
      out.hidden = false;
    }
    input.addEventListener('focus', load, { once: true });
    input.addEventListener('input', function () {
      var q = input.value.trim();
      (index ? Promise.resolve() : load()).then(function () { render(q); });
    });
    input.addEventListener('keydown', function (e) {
      if (e.key === 'Escape') { input.value = ''; render(''); }
      if (e.key === 'Enter') { var first = out.querySelector('a'); if (first) location.href = first.href; }
    });
  }
})();
