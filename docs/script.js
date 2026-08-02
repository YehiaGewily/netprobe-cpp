/* =========================================================================
   NetProbe — landing page behaviour
   - hero inspector (typing hex + layers lighting up + cycling packets)
   - OS install tabs (roving tabindex, arrow-key nav)
   - copy-to-clipboard
   - mobile nav toggle
   - scroll reveals
   ========================================================================= */
(function () {
  "use strict";

  var reduceMotion = window.matchMedia("(prefers-reduced-motion: reduce)").matches;

  /* -----------------------------------------------------------------------
     Packet data — three real, representative packets. Each byte is tagged
     with the layer it belongs to so the hex spans can be tinted and the
     labels lit in sequence. Bytes are plausible for the resolved summary.
     ----------------------------------------------------------------------- */
  var ETH = "00 1a 2b 3c 4d 5e a4 b1 c2 d3 e4 f5 08 00".split(" ");

  var PACKETS = [
    {
      proto: "TCP · TLS",
      descs: { frame: "Ethernet II", network: "IPv4", transport: "TCP", application: "TLS ClientHello" },
      layers: [
        { name: "frame", bytes: ETH },
        { name: "network", bytes: "45 00 00 3c 1a f2 40 00 40 06 b1 e6 0a 00 00 0e 5d b8 d8 22".split(" ") },
        { name: "transport", bytes: "c8 de 01 bb".split(" ") },
        { name: "application", bytes: "16 03 01 00 c7".split(" ") }
      ],
      summary: [
        { c: "lbl", t: "TCP " },
        { t: "10.0.0.14:51422 → 93.184.216.34:443" },
        { t: "   ·   " },
        { c: "amp", t: "TLS ClientHello" },
        { t: "   ·   SNI " },
        { c: "lbl", t: "example.com" },
        { t: "   ·   RTT 18 ms" }
      ]
    },
    {
      proto: "UDP · QUIC",
      descs: { frame: "Ethernet II", network: "IPv4", transport: "UDP", application: "QUIC Initial" },
      layers: [
        { name: "frame", bytes: ETH },
        { name: "network", bytes: "45 00 00 4a 3b 1c 40 00 40 11 7d 22 0a 00 00 0e 8e fa 48 c4".split(" ") },
        { name: "transport", bytes: "d3 c2 01 bb".split(" ") },
        { name: "application", bytes: "c3 00 00 00 01".split(" ") }
      ],
      summary: [
        { c: "lbl", t: "UDP " },
        { t: "10.0.0.14:54210 → 142.250.72.196:443" },
        { t: "   ·   " },
        { c: "amp", t: "QUIC Initial v1" },
        { t: "   ·   SNI " },
        { c: "lbl", t: "www.google.com" }
      ]
    },
    {
      proto: "UDP · DNS",
      descs: { frame: "Ethernet II", network: "IPv4", transport: "UDP", application: "DNS query" },
      layers: [
        { name: "frame", bytes: ETH },
        { name: "network", bytes: "45 00 00 3a 7c 4e 40 00 40 11 5a 3c 0a 00 00 0e 08 08 08 08".split(" ") },
        { name: "transport", bytes: "cb 21 00 35".split(" ") },
        { name: "application", bytes: "12 34 01 00 00 01".split(" ") }
      ],
      summary: [
        { c: "lbl", t: "UDP " },
        { t: "10.0.0.14:52001 → 8.8.8.8:53" },
        { t: "   ·   " },
        { c: "amp", t: "DNS A?" },
        { t: "   ·   " },
        { c: "lbl", t: "cloudflare.com" }
      ]
    }
  ];

  var LAYER_ORDER = ["frame", "network", "transport", "application"];

  var hexEl = document.getElementById("decode-hex");
  var summaryEl = document.getElementById("decode-summary");
  var indexEl = document.getElementById("decode-index");
  var protoEl = document.getElementById("decode-proto");
  var layersWrap = document.getElementById("decode-layers");

  if (hexEl && summaryEl && layersWrap) {
    var layerEls = {};
    LAYER_ORDER.forEach(function (name) {
      layerEls[name] = layersWrap.querySelector('.layer[data-layer="' + name + '"]');
    });

    var timers = [];
    function later(fn, ms) { var id = setTimeout(fn, ms); timers.push(id); return id; }
    function clearTimers() { timers.forEach(clearTimeout); timers = []; }

    function setDescs(descs) {
      LAYER_ORDER.forEach(function (name) {
        var d = layerEls[name].querySelector('[data-desc="' + name + '"]');
        if (d) d.textContent = descs[name];
      });
    }

    function resetLayers() {
      LAYER_ORDER.forEach(function (name) { layerEls[name].classList.remove("is-lit"); });
    }

    function summaryHTML(parts) {
      return parts.map(function (p) {
        var cls = p.c ? ' class="' + p.c + '"' : "";
        return "<span" + cls + ">" + p.t + "</span>";
      }).join("");
    }

    function flatten(packet) {
      var out = [];
      packet.layers.forEach(function (layer) {
        layer.bytes.forEach(function (b, i) {
          out.push({ v: b, layer: layer.name, end: i === layer.bytes.length - 1 });
        });
      });
      return out;
    }

    function renderStatic(packet) {
      indexEl.textContent = "01";
      protoEl.textContent = packet.proto;
      setDescs(packet.descs);
      hexEl.innerHTML = "";
      flatten(packet).forEach(function (b) {
        var span = document.createElement("span");
        span.className = "hx hx--" + b.layer + " is-on is-lit";
        span.textContent = b.v;
        hexEl.appendChild(span);
      });
      LAYER_ORDER.forEach(function (name) { layerEls[name].classList.add("is-lit"); });
      summaryEl.innerHTML = summaryHTML(packet.summary);
    }

    function typeSummary(parts, done) {
      var idx = 0, pos = 0;
      summaryEl.innerHTML = "";
      function step() {
        if (idx >= parts.length) {
          summaryEl.classList.remove("cursor");
          if (done) done();
          return;
        }
        var part = parts[idx];
        var spanId = "sum-" + idx;
        var span = document.getElementById(spanId);
        if (!span) {
          span = document.createElement("span");
          span.id = spanId;
          if (part.c) span.className = part.c;
          summaryEl.appendChild(span);
        }
        span.textContent += part.t.charAt(pos);
        pos++;
        if (pos >= part.t.length) { idx++; pos = 0; }
        later(step, 12);
      }
      summaryEl.classList.add("cursor");
      step();
    }

    function playPacket(pIndex, onComplete) {
      var packet = PACKETS[pIndex];
      clearTimers();
      resetLayers();
      hexEl.innerHTML = "";
      summaryEl.innerHTML = "";
      summaryEl.classList.remove("cursor");
      indexEl.textContent = ("0" + (pIndex + 1)).slice(-2);
      protoEl.textContent = packet.proto;
      setDescs(packet.descs);

      var seq = flatten(packet);
      var prevActive = null;

      function typeByte(i) {
        if (i >= seq.length) {
          later(function () {
            typeSummary(packet.summary, function () {
              later(onComplete, 2400);
            });
          }, 260);
          return;
        }
        var b = seq[i];
        var span = document.createElement("span");
        span.className = "hx hx--" + b.layer + " is-on is-active";
        span.textContent = b.v;
        hexEl.appendChild(span);

        if (prevActive) prevActive.classList.remove("is-active");
        prevActive = span;

        if (b.end) {
          var lit = hexEl.querySelectorAll(".hx--" + b.layer);
          lit.forEach(function (el) { el.classList.add("is-lit"); });
          layerEls[b.layer].classList.add("is-lit");
        }
        later(function () { typeByte(i + 1); }, 34);
      }
      typeByte(0);
    }

    if (reduceMotion) {
      renderStatic(PACKETS[0]);
    } else {
      var current = 0, started = false;
      function cycle() {
        playPacket(current, function () {
          current = (current + 1) % PACKETS.length;
          cycle();
        });
      }
      if ("IntersectionObserver" in window) {
        var io = new IntersectionObserver(function (entries) {
          entries.forEach(function (e) {
            if (e.isIntersecting && !started) {
              started = true;
              cycle();
              io.disconnect();
            }
          });
        }, { threshold: 0.25 });
        io.observe(document.getElementById("decode"));
      } else {
        cycle();
      }
    }
  }

  /* -----------------------------------------------------------------------
     OS install tabs — roving tabindex + arrow-key navigation
     ----------------------------------------------------------------------- */
  var tablist = document.querySelector(".tabs");
  if (tablist) {
    var tabs = Array.prototype.slice.call(tablist.querySelectorAll('[role="tab"]'));

    function selectTab(tab, focus) {
      tabs.forEach(function (t) {
        var selected = t === tab;
        t.setAttribute("aria-selected", String(selected));
        t.tabIndex = selected ? 0 : -1;
        var panel = document.getElementById(t.getAttribute("aria-controls"));
        if (panel) panel.hidden = !selected;
      });
      if (focus) tab.focus();
    }

    tabs.forEach(function (tab, i) {
      tab.addEventListener("click", function () { selectTab(tab, false); });
      tab.addEventListener("keydown", function (e) {
        var next;
        if (e.key === "ArrowRight" || e.key === "ArrowDown") next = tabs[(i + 1) % tabs.length];
        else if (e.key === "ArrowLeft" || e.key === "ArrowUp") next = tabs[(i - 1 + tabs.length) % tabs.length];
        else if (e.key === "Home") next = tabs[0];
        else if (e.key === "End") next = tabs[tabs.length - 1];
        if (next) { e.preventDefault(); selectTab(next, true); }
      });
    });
  }

  /* -----------------------------------------------------------------------
     Copy-to-clipboard
     ----------------------------------------------------------------------- */
  document.querySelectorAll(".copy-btn").forEach(function (btn) {
    btn.addEventListener("click", function () {
      var block = btn.closest(".codeblock");
      var code = block ? block.querySelector("code") : null;
      if (!code) return;
      var text = code.innerText;
      var label = btn.querySelector(".copy-label");

      function done() {
        btn.classList.add("is-done");
        if (label) label.textContent = "Copied";
        setTimeout(function () {
          btn.classList.remove("is-done");
          if (label) label.textContent = "Copy";
        }, 1600);
      }

      if (navigator.clipboard && navigator.clipboard.writeText) {
        navigator.clipboard.writeText(text).then(done).catch(fallback);
      } else {
        fallback();
      }

      function fallback() {
        var ta = document.createElement("textarea");
        ta.value = text;
        ta.setAttribute("readonly", "");
        ta.style.position = "absolute";
        ta.style.left = "-9999px";
        document.body.appendChild(ta);
        ta.select();
        try { document.execCommand("copy"); done(); } catch (err) { /* no-op */ }
        document.body.removeChild(ta);
      }
    });
  });

  /* -----------------------------------------------------------------------
     Mobile nav toggle
     ----------------------------------------------------------------------- */
  var toggle = document.querySelector(".nav__toggle");
  var links = document.getElementById("nav-links");
  if (toggle && links) {
    toggle.addEventListener("click", function () {
      var open = links.classList.toggle("is-open");
      toggle.setAttribute("aria-expanded", String(open));
    });
    links.addEventListener("click", function (e) {
      if (e.target.closest("a")) {
        links.classList.remove("is-open");
        toggle.setAttribute("aria-expanded", "false");
      }
    });
  }

  /* Section entrance is a pure-CSS load animation (.reveal) — no JS gating,
     so content is never hidden if scripts are slow, blocked, or disabled. */
})();
