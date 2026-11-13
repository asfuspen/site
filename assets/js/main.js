(function () {
  "use strict";
  var doc = document, root = doc.documentElement;
  var reduce = matchMedia("(prefers-reduced-motion: reduce)").matches;
  var L = {};
  try { L = JSON.parse(doc.body.dataset.t || "{}"); } catch (e) {}
  var t = function (k, d) { return L[k] || d; };

  // Tema claro e escuro
  doc.querySelectorAll("[data-toggle-theme]").forEach(function (b) {
    b.addEventListener("click", function () {
      var t = root.dataset.theme === "light" ? "dark" : "light";
      root.dataset.theme = t;
      try { localStorage.setItem("tema", t); } catch (e) {}
    });
  });

  // Barra de progresso de leitura
  var bar = doc.querySelector(".progress span");
  if (bar && doc.querySelector(".post")) {
    var onScroll = function () {
      var h = doc.documentElement.scrollHeight - innerHeight;
      bar.style.width = (h > 0 ? Math.min(100, (scrollY / h) * 100) : 0) + "%";
    };
    addEventListener("scroll", onScroll, { passive: true });
    onScroll();
  }

  // Entrada suave dos elementos
  var reveals = doc.querySelectorAll(".reveal");
  if (reduce || !("IntersectionObserver" in window)) {
    reveals.forEach(function (el) { el.classList.add("in"); });
  } else {
    var io = new IntersectionObserver(function (entries) {
      entries.forEach(function (e) {
        if (e.isIntersecting) { e.target.classList.add("in"); io.unobserve(e.target); }
      });
    }, { rootMargin: "0px 0px -8% 0px" });
    reveals.forEach(function (el, i) { el.style.transitionDelay = Math.min(i % 6, 5) * 60 + "ms"; io.observe(el); });
  }

  // Brilho que segue o cursor nos cartões
  doc.querySelectorAll(".card").forEach(function (c) {
    c.addEventListener("pointermove", function (e) {
      var r = c.getBoundingClientRect();
      c.style.setProperty("--mx", e.clientX - r.left + "px");
      c.style.setProperty("--my", e.clientY - r.top + "px");
    });
  });

  // Contadores
  if (!reduce) {
    doc.querySelectorAll("[data-count]").forEach(function (el) {
      var end = parseInt(el.dataset.count, 10) || 0;
      if (end < 2) return;
      var start = performance.now(), dur = 900;
      (function tick(now) {
        var p = Math.min(1, (now - start) / dur);
        el.textContent = Math.round(end * (1 - Math.pow(1 - p, 3)));
        if (p < 1) requestAnimationFrame(tick);
      })(start);
    });
  }

  // Terminal com efeito de digitação
  var term = doc.querySelector("[data-terminal]");
  if (term && !reduce) {
    var lines = Array.prototype.slice.call(term.children);
    lines.forEach(function (l) { l.classList.add("hide"); });
    var i = 0;
    var next = function () {
      if (i >= lines.length) return;
      var line = lines[i++];
      var typed = line.querySelector("[data-type]");
      line.classList.remove("hide");
      if (!typed) { setTimeout(next, line.classList.contains("cmd") ? 0 : 130); return; }
      var text = typed.textContent, n = 0;
      typed.textContent = "";
      var caret = doc.createElement("span");
      caret.className = "caret";
      typed.after(caret);
      (function type() {
        typed.textContent = text.slice(0, ++n);
        if (n < text.length) setTimeout(type, 38 + Math.random() * 40);
        else setTimeout(function () { caret.remove(); next(); }, 320);
      })();
    };
    setTimeout(next, 450);
  }

  // Terminal interativo: aceita comandos de verdade
  var tform = doc.querySelector("[data-term-form]");
  if (tform && term) {
    var tin = tform.querySelector("input"), en = /^en/i.test(root.lang || ""), tdata = null, hist = [], hpos = 0;
    var S = en ? {
      help: [["help", "show this list"], ["ls [posts|kql|tags]", "list content"], ["open <name|n>", "open a page, post or query"],
        ["kql <term>", "search the KQL library"], ["mitre", "open the ATT&CK map"], ["whoami", "who writes here"],
        ["theme light|dark", "switch the theme"], ["lang", "switch language"], ["social | linkedin | github", "profiles"], ["clear", "clear the screen"]],
      nf: "command not found. Type help.", none: "nothing found.", opening: "opening", usage: "usage:", pages: "pages", theme: "theme set to",
      sudo: "nice try. This incident will be reported.", loading: "loading...", err: "could not load the index.", more: "and more. Refine the search."
    } : {
      help: [["help", "mostra esta lista"], ["ls [posts|kql|tags]", "lista o conteúdo"], ["open <nome|n>", "abre uma página, post ou consulta"],
        ["kql <termo>", "busca na biblioteca KQL"], ["mitre", "abre o mapa ATT&CK"], ["whoami", "quem escreve aqui"],
        ["tema claro|escuro", "troca o tema"], ["lang", "troca o idioma"], ["social | linkedin | github", "perfis"], ["clear", "limpa a tela"]],
      nf: "comando não encontrado. Digite help.", none: "nada encontrado.", opening: "abrindo", usage: "uso:", pages: "páginas", theme: "tema alterado para",
      sudo: "boa tentativa. Este incidente será reportado.", loading: "carregando...", err: "não foi possível carregar o índice.", more: "e mais. Refine a busca."
    };
    var nrm = function (s) { return (s || "").toLowerCase().normalize("NFD").replace(/[̀-ͯ]/g, ""); };
    var put = function (text, cls, href) {
      var p = doc.createElement("p");
      p.className = cls || "out";
      if (href) { var a = doc.createElement("a"); a.href = href; a.textContent = text; p.append(a); }
      else p.textContent = text;
      tform.before(p);
      return p;
    };
    var pair = function (a, b) {
      var p = doc.createElement("p"), x = doc.createElement("span"), y = doc.createElement("span");
      p.className = "out cols"; x.textContent = a; y.textContent = b; p.append(x, y); tform.before(p);
    };
    var load = function () {
      if (tdata) return Promise.resolve(tdata);
      return fetch(doc.body.dataset.index).then(function (r) { return r.json(); }).then(function (j) { tdata = j; return j; });
    };
    var of = function (c) { return tdata.filter(function (it) { return it.c === c; }); };
    var last = [];
    var listing = function (items, max) {
      last = items.slice(0, max || 12);
      if (!last.length) { put(S.none); return; }
      last.forEach(function (it, n) { put((n + 1) + "  " + it.t, "out", it.u); });
      if (items.length > last.length) put(S.more, "out tip");
    };
    var go = function (it) { put(S.opening + " " + it.t + "...", "out ok"); setTimeout(function () { location.href = it.u; }, 350); };
    var slug = function (u) { var s = u.replace(/[#?].*$/, "").split("/").filter(Boolean); return s.length ? s[s.length - 1] : ""; };
    var setTheme = function (v) {
      root.dataset.theme = v;
      try { localStorage.setItem("tema", v); } catch (e) {}
      put(S.theme + " " + (en ? v : (v === "light" ? "claro" : "escuro")) + ".", "out ok");
    };
    var run = function (raw) {
      var parts = raw.trim().split(/\s+/), cmd = nrm(parts[0]), arg = nrm(parts.slice(1).join(" ")).replace(/\/+$/, "");
      if (cmd === "help" || cmd === "ajuda" || cmd === "?") { S.help.forEach(function (h) { pair(h[0], h[1]); }); return; }
      if (cmd === "clear" || cmd === "cls" || cmd === "limpar") {
        Array.prototype.slice.call(term.children).forEach(function (el) { if (el !== tform) el.remove(); });
        return;
      }
      if (cmd === "whoami") { put(tform.dataset.who || ""); return; }
      if (cmd === "date" || cmd === "data") { put(new Date().toLocaleString(root.lang || "pt-BR")); return; }
      if (cmd === "sudo" || cmd === "su" || cmd === "rm") { put(S.sudo); return; }
      if (cmd === "echo") { put(parts.slice(1).join(" ")); return; }
      if (cmd === "pwd") { put(location.pathname); return; }
      if (cmd === "tema" || cmd === "theme") {
        if (/^(claro|light)$/.test(arg)) setTheme("light");
        else if (/^(escuro|dark)$/.test(arg)) setTheme("dark");
        else put(S.usage + " " + (en ? "theme light|dark" : "tema claro|escuro"));
        return;
      }
      if (cmd === "lang" || cmd === "idioma") {
        var alt = doc.querySelector("a.lang[hreflang]");
        if (alt) go({ t: alt.getAttribute("hreflang"), u: alt.href }); else put(S.none);
        return;
      }
      if (cmd === "linkedin" || cmd === "github") {
        var prof = doc.querySelector('a[rel~=me][href*="' + cmd + '."]');
        if (prof) { put(S.opening + " " + cmd + "...", "out ok"); window.open(prof.href, "_blank", "noopener"); } else put(S.none);
        return;
      }
      if (cmd === "social") {
        var seen = {};
        doc.querySelectorAll("a[rel~=me]").forEach(function (a) {
          if (seen[a.href]) return; seen[a.href] = 1;
          put(a.getAttribute("aria-label") || a.textContent.trim() || a.href, "out", a.href);
        });
        return;
      }
      var wait = put(S.loading, "out tip");
      return load().then(function () {
        wait.remove();
        var pages = of("page");
        if (cmd === "mitre" || cmd === "attack") {
          var m = pages.filter(function (it) { return slug(it.u) === "mitre"; })[0];
          if (m) go(m); else put(S.none);
        } else if (cmd === "ls" || cmd === "dir") {
          var w = arg.replace(/^-\S+\s*/, "");
          if (/^post|^blog/.test(w)) listing(of("post"));
          else if (/^kql/.test(w)) listing(of("kql"));
          else if (/^tag|^topic|^tema/.test(w)) listing(of("topic"), 20);
          else { listing(pages); put("posts/  kql/  tags/", "out tip"); }
        } else if (cmd === "kql") {
          if (!arg) listing(of("kql"));
          else listing(of("kql").filter(function (it) { return nrm(it.t + " " + it.s).indexOf(arg) > -1; }));
        } else if (cmd === "open" || cmd === "cat" || cmd === "cd" || cmd === "abrir") {
          if (!arg) { put(S.usage + " open <" + (en ? "name|n" : "nome|n") + ">"); return; }
          if (arg === "~" || arg === "home" || arg === "inicio") { go({ t: "~", u: doc.body.dataset.home }); return; }
          var n = parseInt(arg, 10), hit = null;
          if (String(n) === arg && last[n - 1]) hit = last[n - 1];
          if (!hit) {
            var a = arg.replace(/^posts\/|^kql\/|\.(md|kql|txt)$/g, "");
            hit = tdata.filter(function (it) { return slug(it.u) === a || nrm(it.t) === a || (it.u.split("#")[1] || "") === a; })[0] ||
              tdata.filter(function (it) { return nrm(it.t).indexOf(a) > -1; })[0];
          }
          if (hit) go(hit); else put(S.none);
        } else put(parts[0] + ": " + S.nf);
      }).catch(function () { wait.remove(); put(S.err); });
    };
    var names = ["help", "ls", "open", "kql", "mitre", "whoami", en ? "theme" : "tema", "lang", "social", "linkedin", "github", "clear", "date"];
    tform.addEventListener("submit", function (e) {
      e.preventDefault();
      var v = tin.value.trim();
      if (!v) return;
      tin.value = "";
      hist.push(v); hpos = hist.length;
      var p = doc.createElement("p"), ps = doc.createElement("span");
      p.className = "cmd echo"; ps.className = "ps"; ps.textContent = "$";
      p.append(ps, " " + v); tform.before(p);
      var done = function () { term.scrollTop = term.scrollHeight; };
      var r = run(v);
      if (r && r.then) r.then(done); else done();
    });
    tin.addEventListener("keydown", function (e) {
      if (e.key === "ArrowUp" && hist.length) { e.preventDefault(); hpos = Math.max(0, hpos - 1); tin.value = hist[hpos]; }
      else if (e.key === "ArrowDown" && hist.length) { e.preventDefault(); hpos = Math.min(hist.length, hpos + 1); tin.value = hist[hpos] || ""; }
      else if (e.key === "Tab" && tin.value && tin.value.indexOf(" ") < 0) {
        var c = names.filter(function (x) { return x.indexOf(nrm(tin.value)) === 0; });
        if (c.length === 1) { e.preventDefault(); tin.value = c[0] + " "; }
      } else if (e.key === "l" && e.ctrlKey) { e.preventDefault(); run("clear"); }
    });
    term.addEventListener("click", function (e) {
      if (e.target.closest("a") || String(getSelection())) return;
      tin.focus({ preventScroll: true });
    });
  }

  // Mapa ATT&CK: filtra as detecções pela tática escolhida
  var mitre = doc.querySelector("[data-mitre]");
  if (mitre) {
    var tacs = mitre.querySelectorAll(".tactic"), rows = mitre.querySelectorAll(".mitre-list li"),
      hint = mitre.querySelector("[data-mitre-hint]"), all = mitre.querySelector("[data-mitre-all]"), hint0 = hint ? hint.textContent : "";
    var pick = function (id) {
      tacs.forEach(function (b) { b.setAttribute("aria-selected", b.dataset.tactic === id ? "true" : "false"); });
      rows.forEach(function (li) { li.hidden = !!id && li.dataset.tactic !== id; });
      if (all) all.hidden = !id;
      if (hint) {
        var b = id && mitre.querySelector('.tactic[data-tactic="' + id + '"]');
        hint.textContent = b ? b.querySelector(".t-id").textContent + " · " + b.querySelector(".t-name").textContent : hint0;
      }
    };
    tacs.forEach(function (b) {
      b.addEventListener("click", function () {
        if (b.disabled) return;
        pick(b.getAttribute("aria-selected") === "true" ? "" : b.dataset.tactic);
      });
    });
    if (all) all.addEventListener("click", function () { pick(""); });
    var h = location.hash.slice(1).toUpperCase();
    if (/^TA\d{4}$/.test(h) && mitre.querySelector('.tactic[data-tactic="' + h + '"]:not([disabled])')) pick(h);
  }

  // Rede animada no fundo do topo
  var cv = doc.querySelector(".net");
  if (cv && !reduce && cv.getContext) {
    var ctx = cv.getContext("2d"), pts = [], w = 0, h = 0, dpr = Math.min(devicePixelRatio || 1, 2), raf = 0, visible = true;
    var size = function () {
      var r = cv.getBoundingClientRect();
      w = r.width; h = r.height;
      cv.width = w * dpr; cv.height = h * dpr;
      ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
      var count = Math.max(18, Math.min(70, Math.round((w * h) / 17000)));
      pts = [];
      for (var k = 0; k < count; k++) pts.push({ x: Math.random() * w, y: Math.random() * h, vx: (Math.random() - .5) * .28, vy: (Math.random() - .5) * .28 });
    };
    var draw = function () {
      var light = root.dataset.theme === "light";
      var rgb = light ? "7,134,107" : "61,245,196";
      ctx.clearRect(0, 0, w, h);
      for (var a = 0; a < pts.length; a++) {
        var p = pts[a];
        p.x += p.vx; p.y += p.vy;
        if (p.x < 0 || p.x > w) p.vx *= -1;
        if (p.y < 0 || p.y > h) p.vy *= -1;
        ctx.fillStyle = "rgba(" + rgb + ",.75)";
        ctx.beginPath(); ctx.arc(p.x, p.y, 1.5, 0, 6.283); ctx.fill();
        for (var b = a + 1; b < pts.length; b++) {
          var q = pts[b], dx = p.x - q.x, dy = p.y - q.y, d = dx * dx + dy * dy;
          if (d < 19600) {
            ctx.strokeStyle = "rgba(" + rgb + "," + (.32 * (1 - d / 19600)).toFixed(3) + ")";
            ctx.lineWidth = 1;
            ctx.beginPath(); ctx.moveTo(p.x, p.y); ctx.lineTo(q.x, q.y); ctx.stroke();
          }
        }
      }
      if (visible) raf = requestAnimationFrame(draw);
    };
    size();
    addEventListener("resize", size);
    doc.addEventListener("visibilitychange", function () {
      visible = !doc.hidden;
      cancelAnimationFrame(raf);
      if (visible) raf = requestAnimationFrame(draw);
    });
    raf = requestAnimationFrame(draw);
  }

  // Blocos de código com rótulo de linguagem e botão de copiar
  doc.querySelectorAll(".prose pre").forEach(function (pre) {
    var holder = pre.closest(".highlight") || pre;
    var code = pre.querySelector("code");
    var lang = code && (code.dataset.lang || (code.className.match(/language-([\w-]+)/) || [])[1]) || t("code", "código");
    if (lang === "kusto") lang = "kql";
    var box = doc.createElement("div"); box.className = "codeblock";
    var top = doc.createElement("div"); top.className = "codebar mono";
    var label = doc.createElement("span"); label.textContent = lang;
    var btn = doc.createElement("button"); btn.type = "button"; btn.textContent = t("copy", "copiar");
    btn.addEventListener("click", function () {
      copy((code || pre).innerText).then(function () {
        btn.textContent = t("copied", "copiado");
        setTimeout(function () { btn.textContent = t("copy", "copiar"); }, 1600);
      });
    });
    top.append(label, btn);
    holder.parentNode.insertBefore(box, holder);
    box.append(top, holder);
  });

  function copy(text) {
    if (navigator.clipboard) return navigator.clipboard.writeText(text);
    return new Promise(function (ok) {
      var ta = doc.createElement("textarea");
      ta.value = text; doc.body.append(ta); ta.select();
      try { doc.execCommand("copy"); } catch (e) {}
      ta.remove(); ok();
    });
  }

  doc.querySelectorAll("[data-copy-link]").forEach(function (b) {
    b.addEventListener("click", function () {
      copy(b.dataset.copyLink).then(function () {
        var old = b.textContent; b.textContent = t("linkCopied", "link copiado");
        setTimeout(function () { b.textContent = old; }, 1600);
      });
    });
  });

  // Brilho que acompanha o cursor no topo
  var hero = doc.querySelector("[data-spot]");
  if (hero && !reduce && matchMedia("(hover: hover)").matches) {
    hero.addEventListener("pointermove", function (e) {
      var r = hero.getBoundingClientRect();
      hero.style.setProperty("--sx", e.clientX - r.left + "px");
      hero.style.setProperty("--sy", e.clientY - r.top + "px");
      hero.classList.add("spot");
    });
    hero.addEventListener("pointerleave", function () { hero.classList.remove("spot"); });
  }

  // Biblioteca KQL: filtro por texto e por produto
  var kql = doc.querySelector("[data-kql]");
  if (kql) {
    var kin = kql.querySelector("input"), kitems = kql.querySelectorAll(".kql"), kcount = kql.querySelector("[data-kql-count]"),
      kempty = kql.querySelector("[data-kql-empty]"), kchips = kql.querySelectorAll("[data-prod]:not(.kql)"), prod = "";
    var strip = function (v) { return (v || "").toLowerCase().normalize("NFD").replace(/[\u0300-\u036f]/g, ""); };
    var apply = function () {
      var terms = strip(kin.value).split(/\s+/).filter(Boolean), n = 0;
      kitems.forEach(function (el) {
        var hay = strip(el.dataset.text + " " + el.querySelector("pre").textContent);
        var ok = (!prod || el.dataset.prod === prod) && terms.every(function (w) { return hay.indexOf(w) > -1; });
        el.hidden = !ok; if (ok) { n++; el.classList.add("in"); }
      });
      kcount.textContent = n; kempty.hidden = n > 0;
    };
    kin.addEventListener("input", apply);
    kchips.forEach(function (c) {
      c.addEventListener("click", function () {
        prod = c.dataset.prod;
        kchips.forEach(function (o) { o.classList.toggle("on", o === c); });
        apply();
      });
    });
  }

  // Destaque da seção atual no sumário
  var tocLinks = doc.querySelectorAll(".toc a");
  if (tocLinks.length && "IntersectionObserver" in window) {
    var map = {};
    tocLinks.forEach(function (a) { map[decodeURIComponent(a.hash.slice(1))] = a; });
    var spy = new IntersectionObserver(function (entries) {
      entries.forEach(function (e) {
        if (e.isIntersecting && map[e.target.id]) {
          tocLinks.forEach(function (a) { a.classList.remove("on"); });
          map[e.target.id].classList.add("on");
        }
      });
    }, { rootMargin: "-15% 0px -70% 0px" });
    doc.querySelectorAll(".prose h2[id], .prose h3[id]").forEach(function (hd) { spy.observe(hd); });
  }

  // Busca por atalho (Ctrl K ou /)
  var pal = doc.querySelector(".palette");
  if (pal) {
    var input = pal.querySelector("input"), list = pal.querySelector(".palette-list");
    var data = null, shown = [], sel = 0, lastFocus = null;
    var norm = function (s) { return (s || "").toLowerCase().normalize("NFD").replace(/[̀-ͯ]/g, ""); };
    var render = function () {
      var q = norm(input.value.trim()), terms = q.split(/\s+/).filter(Boolean);
      shown = (data || []).filter(function (it) {
        var hay = norm(it.t + " " + it.s + " " + it.k);
        return terms.every(function (t) { return hay.indexOf(t) > -1; });
      }).slice(0, 12);
      sel = 0;
      list.textContent = "";
      if (!shown.length) {
        var li = doc.createElement("li"); li.className = "none";
        li.textContent = data ? t("none", "Nada encontrado.") : t("loading", "Carregando...");
        list.append(li); return;
      }
      shown.forEach(function (it, idx) {
        var li = doc.createElement("li"), a = doc.createElement("span"), k = doc.createElement("span");
        a.textContent = it.t; k.textContent = it.k;
        li.setAttribute("role", "option"); li.setAttribute("aria-selected", idx === 0 ? "true" : "false");
        li.append(a, k);
        li.addEventListener("click", function () { location.href = it.u; });
        li.addEventListener("pointermove", function () { mark(idx); });
        list.append(li);
      });
    };
    var mark = function (idx) {
      sel = idx;
      Array.prototype.forEach.call(list.children, function (li, n) {
        li.setAttribute("aria-selected", n === sel ? "true" : "false");
        if (n === sel) li.scrollIntoView({ block: "nearest" });
      });
    };
    var open = function () {
      lastFocus = doc.activeElement;
      pal.hidden = false; input.value = ""; render(); input.focus();
      if (!data) {
        fetch(doc.body.dataset.index).then(function (r) { return r.json(); })
          .then(function (j) { data = j; render(); })
          .catch(function () { data = []; render(); });
      }
    };
    var close = function () { pal.hidden = true; if (lastFocus) lastFocus.focus(); };
    doc.querySelectorAll("[data-open-palette]").forEach(function (b) { b.addEventListener("click", open); });
    pal.addEventListener("click", function (e) { if (e.target === pal) close(); });
    input.addEventListener("input", render);
    doc.addEventListener("keydown", function (e) {
      var typing = /^(INPUT|TEXTAREA|SELECT)$/.test((e.target.tagName || ""));
      if ((e.key === "k" && (e.ctrlKey || e.metaKey)) || (e.key === "/" && !typing && pal.hidden)) {
        e.preventDefault(); pal.hidden ? open() : close(); return;
      }
      if (pal.hidden) return;
      if (e.key === "Escape") close();
      else if (e.key === "ArrowDown") { e.preventDefault(); if (shown.length) mark((sel + 1) % shown.length); }
      else if (e.key === "ArrowUp") { e.preventDefault(); if (shown.length) mark((sel - 1 + shown.length) % shown.length); }
      else if (e.key === "Enter" && shown[sel]) location.href = shown[sel].u;
      else if (e.key === "Tab") { e.preventDefault(); input.focus(); }
    });
  }
})();
