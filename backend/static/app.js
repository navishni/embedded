// Sentinel dashboard behaviour. External file so the CSP can forbid inline scripts.
(function () {
  "use strict";
  const csrf = document.querySelector('meta[name="csrf-token"]').content;
  const page = document.body.dataset.page;
  const loggedIn = document.body.classList.contains("app");
  const $ = (id) => document.getElementById(id);

  // ------------------------------------------------------------ helpers
  async function api(url, options = {}) {
    const opts = Object.assign({ credentials: "same-origin", headers: {} }, options);
    if (opts.method && opts.method !== "GET") opts.headers["X-CSRF-Token"] = csrf;
    if (opts.json !== undefined) {
      opts.headers["Content-Type"] = "application/json";
      opts.body = JSON.stringify(opts.json);
    }
    const res = await fetch(url, opts);
    if (res.status === 401) { location.href = "/login"; throw new Error("unauthorised"); }
    const data = res.headers.get("content-type")?.includes("json") ? await res.json() : null;
    if (!res.ok) throw new Error((data && data.error) || res.statusText);
    return data;
  }
  const store = {
    get(k, d) { try { const v = localStorage.getItem(k); return v === null ? d : v; } catch { return d; } },
    set(k, v) { try { localStorage.setItem(k, v); } catch { /* storage unavailable */ } },
  };
  const fmtTime = (ts) => new Date(ts * 1000).toLocaleString();
  const fmtShort = (ts) => new Date(ts * 1000).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" });
  function ago(ts) {
    const s = Math.max(0, Math.round(Date.now() / 1000 - ts));
    if (s < 60) return `${s}s ago`;
    if (s < 3600) return `${Math.floor(s / 60)} min ago`;
    if (s < 86400) return `${Math.floor(s / 3600)} h ago`;
    return `${Math.floor(s / 86400)} d ago`;
  }
  function el(tag, attrs = {}, ...children) {
    const e = document.createElement(tag);
    for (const [k, v] of Object.entries(attrs)) {
      if (k === "class") e.className = v; else e.setAttribute(k, v);
    }
    for (const c of children) e.append(c instanceof Node ? c : document.createTextNode(c ?? ""));
    return e;
  }
  function toast(msg, kind = "") {
    const box = $("toasts");
    if (!box) return;
    const t = el("div", { class: `toast ${kind}` }, msg);
    box.append(t);
    setTimeout(() => t.remove(), 4000);
  }
  const chainBadge = (s) => el("span", { class: `badge ${s}` }, s);
  const confMeter = (c) => {
    const m = el("span", { class: "meter" }, el("span"));
    m.firstChild.style.width = `${Math.round(c * 100)}%`;
    return el("span", { class: "conf" }, m, `${Math.round(c * 100)}%`);
  };

  document.querySelectorAll("[data-ts]").forEach((n) => { n.textContent = fmtTime(+n.dataset.ts); });
  document.querySelectorAll(".meter [data-width]").forEach((n) => { n.style.width = n.dataset.width + "%"; });
  document.querySelectorAll("form.confirm").forEach((f) =>
    f.addEventListener("submit", (e) => { if (!confirm(f.dataset.confirm)) e.preventDefault(); }));

  if (!loggedIn) return;

  // ------------------------------------------------------------ sidebar (mobile)
  $("menu-btn")?.addEventListener("click", () => document.body.classList.toggle("nav-open"));
  $("scrim")?.addEventListener("click", () => document.body.classList.remove("nav-open"));

  // ------------------------------------------------------------ arm / disarm pill
  const pill = $("arm-pill");
  let armSettings = null;
  function renderArm(status) {
    if (!status) return;
    pill.classList.toggle("armed", status.armed);
    pill.classList.toggle("disarmed", !status.armed);
    pill.querySelector(".arm-text").textContent = status.armed ? "Armed" : "Disarmed";
    pill.title = status.reason + (pill.dataset.admin === "1" ? " - click to toggle" : "");
    document.dispatchEvent(new CustomEvent("arm-changed", { detail: status }));
  }
  pill.addEventListener("click", async () => {
    if (pill.dataset.admin !== "1") return;
    try {
      if (!armSettings) armSettings = (await api("/api/settings")).settings;
      const want = !armSettings.armed;
      if (!want && !confirm("Disarm the system? No incidents or alarms will be raised.")) return;
      const s = await api("/api/settings", { method: "POST", json: { armed: want } });
      armSettings = s.settings;
      renderArm(s);
      toast(s.armed ? "System armed" : "System disarmed", s.armed ? "ok" : "");
    } catch (e) { toast("Could not change arming: " + e.message, "error"); }
  });

  // ------------------------------------------------------------ alarm sound (Web Audio siren)
  // Browsers block audio until the user interacts with the page, so the context is
  // (re)unlocked on every click/key until it runs, and a blocked siren starts then.
  let audioCtx = null, siren = null;
  let soundOn = store.get("alarmSound", "1") === "1";
  const soundBtn = $("sound-btn");
  const audioReady = () => audioCtx && audioCtx.state === "running";
  const renderSound = () => {
    soundBtn.classList.toggle("muted", !soundOn);
    soundBtn.title = !soundOn ? "Alarm sound muted - click to enable"
      : audioReady() ? "Alarm sound on - click to mute" : "Alarm sound on (click anywhere on the page to allow audio)";
  };
  async function unlockAudio() {
    try {
      if (!audioCtx) audioCtx = new (window.AudioContext || window.webkitAudioContext)();
      if (audioCtx.state !== "running") await audioCtx.resume();
    } catch { return; }
    renderSound();
    if (audioReady()) {
      ["click", "keydown", "touchstart"].forEach((ev) => document.removeEventListener(ev, unlockAudio, true));
      updateSiren();                       // an alarm may already be waiting for sound
    }
  }
  ["click", "keydown", "touchstart"].forEach((ev) => document.addEventListener(ev, unlockAudio, true));
  renderSound();

  function beep(ms = 350, freq = 880) {
    if (!audioReady()) return;
    const o = audioCtx.createOscillator(), g = audioCtx.createGain();
    o.type = "square"; o.frequency.value = freq;
    g.gain.setValueAtTime(0.2, audioCtx.currentTime);
    g.gain.exponentialRampToValueAtTime(0.001, audioCtx.currentTime + ms / 1000);
    o.connect(g).connect(audioCtx.destination);
    o.start(); o.stop(audioCtx.currentTime + ms / 1000);
  }
  soundBtn.addEventListener("click", async () => {
    soundOn = !soundOn;
    store.set("alarmSound", soundOn ? "1" : "0");
    await unlockAudio();
    renderSound();
    if (soundOn) { beep(250, 660); setTimeout(() => beep(250, 990), 280); toast("Alarm sound on (test beep played)", "ok"); }
    else toast("Alarm sound muted");
    updateSiren();
  });

  function startSiren() {
    if (siren || !audioReady()) return;
    const osc = audioCtx.createOscillator(), osc2 = audioCtx.createOscillator(), gain = audioCtx.createGain();
    osc.type = "square"; osc2.type = "sawtooth";
    gain.gain.value = 0.18;
    osc.connect(gain); osc2.connect(gain); gain.connect(audioCtx.destination);
    let up = true;
    const sweep = () => {
      const t = audioCtx.currentTime;
      for (const [o, k] of [[osc, 1], [osc2, 1.5]]) {
        o.frequency.cancelScheduledValues(t);
        o.frequency.setValueAtTime((up ? 600 : 1300) * k, t);
        o.frequency.linearRampToValueAtTime((up ? 1300 : 600) * k, t + 0.45);
      }
      up = !up;
    };
    sweep();
    osc.start(); osc2.start();
    siren = { osc, osc2, timer: setInterval(sweep, 450) };
  }
  function stopSiren() {
    if (!siren) return;
    clearInterval(siren.timer);
    try { siren.osc.stop(); siren.osc2.stop(); } catch { /* already stopped */ }
    siren = null;
  }

  // ------------------------------------------------------------ desktop notifications
  const notifyBtn = $("notify-btn");
  const renderNotify = () => notifyBtn.classList.toggle("active", "Notification" in window && Notification.permission === "granted");
  renderNotify();
  notifyBtn.addEventListener("click", async () => {
    if (!("Notification" in window)) return toast("This browser does not support notifications", "error");
    if (Notification.permission === "granted") return toast("Desktop notifications are already enabled", "ok");
    const p = await Notification.requestPermission();
    renderNotify();
    toast(p === "granted" ? "Desktop notifications enabled" : "Notifications were blocked in the browser", p === "granted" ? "ok" : "error");
  });

  // ------------------------------------------------------------ global intrusion alarm
  // The alarm is raised by (a) a new unacknowledged incident, or (b) a person standing
  // in the zone right now on an armed camera. The siren keeps sounding while the person
  // is in the zone (or for 30 s after a new incident) until the operator dismisses it.
  const alarm = $("alarm");
  let alarmActive = false, alarmIncident = null, raisedAt = 0, liveIntrusion = false, silenced = false;

  function updateSiren() {
    const shouldRing = alarmActive && soundOn && (liveIntrusion || Date.now() - raisedAt < 30000);
    if (shouldRing && audioReady()) startSiren(); else stopSiren();
  }
  function showAlarm(detail, href, inc) {
    alarmIncident = inc;
    $("alarm-detail").textContent = detail;
    $("alarm-view").href = href;
    $("alarm-ack").hidden = !inc;
    if (!alarmActive) raisedAt = Date.now();
    alarmActive = true;
    alarm.hidden = false;
    document.body.classList.add("alarm-flash");
    if (!document.title.startsWith("🚨")) document.title = "🚨 INTRUSION · " + document.title;
    if (soundOn && !audioReady()) toast("🔊 Click anywhere on the page to hear the alarm");
    updateSiren();
  }
  function clearAlarm() {
    alarmActive = false;
    alarmIncident = null;
    if (liveIntrusion) silenced = true;        // stay quiet until the zone clears
    alarm.hidden = true;
    document.body.classList.remove("alarm-flash");
    document.title = document.title.replace("🚨 INTRUSION · ", "");
    updateSiren();
  }
  $("alarm-close").addEventListener("click", clearAlarm);
  $("alarm-ack").addEventListener("click", async () => {
    if (alarmIncident) {
      try {
        await api(`/api/incident/${encodeURIComponent(alarmIncident.id)}/ack`, { method: "POST" });
        toast("Incident acknowledged", "ok");
      } catch (e) { toast("Acknowledge failed: " + e.message, "error"); }
    }
    clearAlarm();
    pollAlerts();
  });

  let lastSeen = store.get("lastSeenIncident", null);
  const openBadge = document.querySelector("[data-open-count]");
  async function pollAlerts() {
    let a;
    try { a = await api("/api/alerts"); } catch { return; }
    openBadge.hidden = !a.open;
    openBadge.textContent = a.open;
    renderArm(a.arm);

    const inc = a.latest;
    let newIncident = null;
    if (inc && lastSeen === null) {            // first visit: don't alarm for history
      lastSeen = inc.id; store.set("lastSeenIncident", inc.id);
    } else if (inc && inc.id !== lastSeen) {
      lastSeen = inc.id; store.set("lastSeenIncident", inc.id);
      if (!inc.acknowledged_by) newIncident = inc;
      document.dispatchEvent(new CustomEvent("new-incident", { detail: inc }));
    }

    const hot = Object.entries(a.cameras).filter(([, c]) => c.online && c.intruders);
    liveIntrusion = a.arm.armed && hot.length > 0;
    if (!liveIntrusion) silenced = false;

    if (newIncident) {
      silenced = false;
      showAlarm(`${newIncident.person_count} person(s) in restricted zone · camera ${newIncident.camera_id} · ` +
                `${fmtShort(newIncident.timestamp)} · ${newIncident.id}`,
                `/incident/${encodeURIComponent(newIncident.id)}`, newIncident);
      if ("Notification" in window && Notification.permission === "granted") {
        const n = new Notification("🚨 Intrusion detected", {
          body: `${newIncident.person_count} person(s) in restricted zone — ${newIncident.camera_id}`,
          tag: newIncident.id, requireInteraction: true,
        });
        n.onclick = () => { window.focus(); location.href = `/incident/${encodeURIComponent(newIncident.id)}`; };
      }
    } else if (liveIntrusion && !alarmActive && !silenced) {
      const [cam, c] = hot[0];
      showAlarm(`${c.intruders} person(s) in the restricted zone right now · camera ${cam}`, "/live", null);
    }
    updateSiren();
    document.dispatchEvent(new CustomEvent("alerts", { detail: a }));
  }
  // keep alarm state in sync across tabs
  window.addEventListener("storage", (e) => { if (e.key === "lastSeenIncident") lastSeen = e.newValue; });
  pollAlerts();
  setInterval(pollAlerts, 1500);

  // ------------------------------------------------------------ dashboard
  if (page === "dashboard") {
    async function refresh() {
      let data;
      try { data = await api("/api/incidents?limit=8"); } catch { return; }
      const s = data.stats;
      $("s-open").textContent = s.open ?? 0;
      $("s-open").classList.toggle("hot", (s.open ?? 0) > 0);
      $("s-24h").textContent = s.last_24h ?? 0;
      $("s-total").textContent = s.total ?? 0;
      $("s-chain").textContent = s.on_chain ?? 0;
      $("notify-warning").hidden = data.notifications;

      const list = $("recent-list");
      list.replaceChildren();
      if (!data.incidents.length) list.append(el("div", { class: "muted pad" }, "No incidents yet. The system is watching."));
      for (const inc of data.incidents) {
        list.append(el("a", { class: "list-item", href: `/incident/${encodeURIComponent(inc.id)}` },
          el("span", { class: "list-dot" + (inc.acknowledged_by ? "" : " open") }),
          el("div", { class: "list-main" }, el("strong", {}, inc.id),
            el("span", {}, `${inc.camera_id} · ${inc.person_count} person(s) · ${ago(inc.timestamp)}`)),
          chainBadge(inc.chain_status)));
      }

      const now = Date.now() / 1000;
      let online = 0;
      document.querySelectorAll("[data-camera]").forEach((card) => {
        const cam = data.cameras[card.dataset.camera];
        const status = card.querySelector("[data-cam-status]");
        const isOn = cam && now - cam.at < 15;
        online += isOn ? 1 : 0;
        const alarmNow = isOn && cam.intruders && cam.armed !== false;
        status.textContent = isOn ? (alarmNow ? "INTRUDER" : cam.armed === false ? "disarmed" : "online") : "offline";
        status.className = "badge " + (isOn ? (alarmNow ? "alarm" : cam.armed === false ? "disarmed" : "online") : "");
        card.classList.toggle("alarm", !!alarmNow);
        if (cam) {
          card.querySelector("[data-cam-info]").textContent =
            `${cam.people} visible · ${cam.intruders} in zone · ${isOn ? "live" : "last seen " + ago(cam.at)}`;
          const img = card.querySelector("[data-cam-img]");
          const stream = `/api/stream/${encodeURIComponent(card.dataset.camera)}`;
          if (isOn && !img.src.endsWith(stream)) img.src = stream;
        }
      });
      $("s-cams").textContent = `${online}/${document.querySelectorAll("[data-camera]").length}`;
    }
    async function chart24() {
      let a;
      try { a = await api("/api/analytics?days=1"); } catch { return; }
      const nowH = new Date().getHours();
      const hours = Array.from({ length: 24 }, (_, i) => (nowH - 23 + i + 24) % 24);
      Charts.render($("chart-24h"), () => Charts.bar($("chart-24h"), hours.map((h) => String(h).padStart(2, "0")),
        hours.map((h) => a.hourly[h] || 0), { labelEvery: 3, highlightMax: true, tipLabels: hours.map((h) => `${h}:00–${h}:59`),
          emptyText: "No incidents in the last 24 hours" }));
    }
    refresh(); chart24();
    setInterval(refresh, 3000);
    setInterval(chart24, 30000);
    document.addEventListener("new-incident", () => { refresh(); chart24(); });
  }

  // ------------------------------------------------------------ live view
  if (page === "live") {
    async function status() {
      let data;
      try { data = await api("/api/incidents?limit=1"); } catch { return; }
      const now = Date.now() / 1000;
      document.querySelectorAll("[data-live-camera]").forEach((card) => {
        const cam = data.cameras[card.dataset.liveCamera];
        const badge = card.querySelector("[data-cam-status]");
        const online = cam && now - cam.at < 15;
        const alarmNow = online && cam.intruders && cam.armed !== false;
        badge.textContent = online ? (alarmNow ? "INTRUDER IN ZONE" : cam.armed === false ? "disarmed · watching" : "zone clear") : "offline";
        badge.className = "badge " + (online ? (alarmNow ? "alarm" : cam.armed === false ? "disarmed" : "online") : "");
        card.classList.toggle("alarm", !!alarmNow);
        card.querySelector("[data-rec]").hidden = !online;
        card.querySelector("[data-people]").textContent = cam ? cam.people : "–";
        card.querySelector("[data-intruders]").textContent = cam ? cam.intruders : "–";
        card.querySelector("[data-last]").textContent = cam ? ago(cam.at) : "never";
      });
    }
    status();
    setInterval(status, 1000);
  }

  // ------------------------------------------------------------ incidents list
  if (page === "incidents") {
    const form = $("filters");
    const params = () => new URLSearchParams([...new FormData(form)].filter(([, v]) => v));
    async function load() {
      const p = params();
      $("export-csv").href = "/export/incidents.csv" + (p.toString() ? "?" + p : "");
      let data;
      try { data = await api("/api/incidents/search?" + p); } catch (e) { toast(e.message, "error"); return; }
      const body = $("incident-rows");
      body.replaceChildren();
      if (!data.incidents.length) body.append(el("tr", {}, el("td", { colspan: 8, class: "muted" }, "No incidents match these filters.")));
      for (const inc of data.incidents) {
        const href = `/incident/${encodeURIComponent(inc.id)}`;
        body.append(el("tr", { class: inc.acknowledged_by ? "" : "unacked" },
          el("td", {}, fmtTime(inc.timestamp)),
          el("td", {}, el("a", { href }, inc.id)),
          el("td", {}, inc.camera_id),
          el("td", {}, String(inc.person_count)),
          el("td", {}, confMeter(inc.max_confidence)),
          el("td", {}, chainBadge(inc.chain_status)),
          el("td", {}, inc.acknowledged_by ? el("span", { class: "badge ok" }, `✓ ${inc.acknowledged_by}`) : el("span", { class: "badge open" }, "open")),
          el("td", { class: "right" }, el("a", { class: "btn small ghost", href: `${href}/report.pdf` }, "PDF"))));
      }
      $("result-count").textContent = `${data.incidents.length} incident(s)` + (data.incidents.length >= 500 ? " (showing first 500)" : "");
    }
    let t;
    form.addEventListener("input", () => { clearTimeout(t); t = setTimeout(load, 250); });
    form.addEventListener("reset", () => setTimeout(load, 0));
    form.addEventListener("submit", (e) => { e.preventDefault(); load(); });
    $("ack-all").addEventListener("click", async () => {
      if (!confirm("Acknowledge ALL open incidents?")) return;
      try {
        const r = await api("/api/incidents/ack-all", { method: "POST" });
        toast(`${r.acknowledged} incident(s) acknowledged`, "ok");
        load();
      } catch (e) { toast(e.message, "error"); }
    });
    load();
    document.addEventListener("new-incident", load);
  }

  // ------------------------------------------------------------ analytics
  if (page === "analytics") {
    const WEEK = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"];
    let days = 7;
    async function load() {
      let a;
      try { a = await api(`/api/analytics?days=${days}`); } catch (e) { toast(e.message, "error"); return; }
      const s = a.summary;
      $("a-total").textContent = s.total || 0;
      $("a-people").textContent = s.people || 0;
      $("a-conf").textContent = s.total ? Math.round(s.avg_conf * 100) + "%" : "–";
      $("a-ack").textContent = s.avg_ack_s == null ? "–" : s.avg_ack_s < 60 ? `${Math.round(s.avg_ack_s)} s`
        : s.avg_ack_s < 3600 ? `${Math.round(s.avg_ack_s / 60)} min` : `${(s.avg_ack_s / 3600).toFixed(1)} h`;
      $("a-chain").textContent = s.total ? `${Math.round((s.on_chain / s.total) * 100)}%` : "–";

      // daily series with missing days filled in
      const dLabels = [], dVals = [], dTips = [];
      for (let i = days - 1; i >= 0; i--) {
        const d = new Date(); d.setDate(d.getDate() - i);
        const key = `${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, "0")}-${String(d.getDate()).padStart(2, "0")}`;
        dLabels.push(d.toLocaleDateString([], { day: "numeric", month: "short" }));
        dVals.push(a.daily[key] || 0); dTips.push(key);
      }
      Charts.render($("c-daily"), () => days === 1
        ? Charts.bar($("c-daily"), [dLabels[0]], dVals, { showValues: true })
        : Charts.line($("c-daily"), dLabels, dVals));
      const hours = [...Array(24).keys()];
      Charts.render($("c-hourly"), () => Charts.bar($("c-hourly"), hours.map((h) => String(h).padStart(2, "0")),
        hours.map((h) => a.hourly[h] || 0), { labelEvery: 3, highlightMax: true, tipLabels: hours.map((h) => `${h}:00–${h}:59`) }));
      // SQLite %w: 0 = Sunday -> reorder to Mon..Sun
      Charts.render($("c-weekday"), () => Charts.bar($("c-weekday"), WEEK,
        [1, 2, 3, 4, 5, 6, 0].map((w) => a.weekday[w] || 0), { highlightMax: true, showValues: true }));
      Charts.render($("c-conf"), () => Charts.donut($("c-conf"), [
        { label: "High (≥ 80%)", value: a.confidence.high || 0, color: "#22c483" },
        { label: "Medium (60–80%)", value: a.confidence.medium || 0, color: "#f5a524" },
        { label: "Low (< 60%)", value: a.confidence.low || 0, color: "#ef4452" },
      ], { centerLabel: "incidents" }));
      Charts.render($("c-cams"), () => Charts.hbar($("c-cams"), a.cameras.map((c) => c.camera_id), a.cameras.map((c) => c.n)));
    }
    $("range").addEventListener("click", (e) => {
      const b = e.target.closest("button[data-days]");
      if (!b) return;
      $("range").querySelectorAll("button").forEach((x) => x.classList.toggle("active", x === b));
      days = +b.dataset.days;
      load();
    });
    load();
    document.addEventListener("new-incident", load);
  }

  // ------------------------------------------------------------ arming & schedule
  if (page === "settings") {
    const sw = $("armed-switch"), en = $("sched-enabled");
    function fill(st) {
      const s = st.settings;
      armSettings = s;
      sw.checked = s.armed;
      en.checked = s.schedule.enabled;
      $("sched-start").value = s.schedule.start;
      $("sched-end").value = s.schedule.end;
      $("sched-days").querySelectorAll("input").forEach((c) => { c.checked = s.schedule.days.includes(+c.value); });
      paintHero(st);
    }
    function paintHero(st) {
      $("arm-hero").classList.toggle("off", !st.armed);
      $("arm-state").textContent = st.armed ? "ARMED" : "DISARMED";
      $("arm-reason").textContent = st.reason;
    }
    document.addEventListener("arm-changed", (e) => paintHero(e.detail));
    async function save(changes, okMsg) {
      try {
        const st = await api("/api/settings", { method: "POST", json: changes });
        fill(st); renderArm(st);
        toast(okMsg, "ok");
        $("sched-msg").textContent = "";
      } catch (e) {
        $("sched-msg").textContent = e.message;
        toast(e.message, "error");
        api("/api/settings").then(fill);
      }
    }
    sw.addEventListener("change", () => save({ armed: sw.checked }, sw.checked ? "System armed" : "System disarmed"));
    $("sched-save").addEventListener("click", () => save({
      schedule: {
        enabled: en.checked, start: $("sched-start").value, end: $("sched-end").value,
        days: [...$("sched-days").querySelectorAll("input:checked")].map((c) => +c.value),
      },
    }, "Schedule saved"));
    api("/api/settings").then(fill);
  }

  // ------------------------------------------------------------ incident detail
  if (page === "incident") {
    const id = document.querySelector("[data-incident]").dataset.incident;
    const img = $("evidence"), toggle = $("annotated");
    const setSrc = () => { img.src = img.dataset.src + (toggle.checked ? "?annotated=1" : ""); };
    toggle.addEventListener("change", setSrc);
    setSrc();

    $("ack-btn")?.addEventListener("click", async () => {
      try {
        await api(`/api/incident/${encodeURIComponent(id)}/ack`, { method: "POST" });
        location.reload();
      } catch (e) { toast(e.message, "error"); }
    });

    $("verify-btn").addEventListener("click", async (e) => {
      const btn = e.currentTarget, box = $("verify-result");
      btn.disabled = true;
      box.hidden = false;
      box.className = "verify";
      box.textContent = "Decrypting evidence, recomputing SHA-256 and querying the blockchain…";
      try {
        const r = await api(`/api/incident/${encodeURIComponent(id)}/verify`, { method: "POST" });
        box.className = "verify " + (r.verified ? "ok" : "bad");
        box.replaceChildren(
          el("strong", {}, (r.verified ? "✔ " : "✖ ") + r.status), el("p", {}, r.message),
          el("div", { class: "mono" }, `file  ${r.file_hash ?? "—"}`),
          el("div", { class: "mono" }, `db    ${r.db_hash ?? "—"}`),
          el("div", { class: "mono" }, `chain ${r.chain_hash ?? "—"}`));
      } catch (err) {
        box.className = "verify bad";
        box.textContent = "Verification failed: " + err.message;
      } finally {
        btn.disabled = false;
      }
    });
  }

  // ------------------------------------------------------------ zone editor
  if (page === "zone") {
    const canvas = $("zone-canvas"), ctx = canvas.getContext("2d"), select = $("zone-camera"), msg = $("zone-msg");
    let points = [], frame = null;

    function draw() {
      ctx.clearRect(0, 0, canvas.width, canvas.height);
      if (frame) ctx.drawImage(frame, 0, 0, canvas.width, canvas.height);
      else {
        ctx.fillStyle = "#0f1520"; ctx.fillRect(0, 0, canvas.width, canvas.height);
        ctx.strokeStyle = "#1c2535";
        for (let x = 0; x < canvas.width; x += 40) { ctx.beginPath(); ctx.moveTo(x, 0); ctx.lineTo(x, canvas.height); ctx.stroke(); }
        for (let y = 0; y < canvas.height; y += 40) { ctx.beginPath(); ctx.moveTo(0, y); ctx.lineTo(canvas.width, y); ctx.stroke(); }
      }
      if (!points.length) return;
      ctx.beginPath();
      points.forEach(([x, y], i) => { const px = x * canvas.width, py = y * canvas.height; i ? ctx.lineTo(px, py) : ctx.moveTo(px, py); });
      ctx.closePath();
      ctx.fillStyle = "rgba(239, 68, 82, 0.25)"; ctx.fill();
      ctx.strokeStyle = "#ef4452"; ctx.lineWidth = 2.5; ctx.stroke();
      points.forEach(([x, y], i) => {
        ctx.beginPath(); ctx.arc(x * canvas.width, y * canvas.height, 6, 0, 7);
        ctx.fillStyle = "#fff"; ctx.fill(); ctx.strokeStyle = "#ef4452"; ctx.stroke();
        ctx.fillStyle = "#ef4452"; ctx.font = "bold 11px sans-serif";
        ctx.fillText(String(i + 1), x * canvas.width + 9, y * canvas.height - 8);
      });
      msg.textContent = `${points.length} point(s)` + (points.length < 3 ? " — need at least 3" : "");
    }
    function loadFrame() {
      const im = new Image();
      im.onload = () => { frame = im; canvas.width = im.naturalWidth; canvas.height = im.naturalHeight; draw(); };
      im.onerror = () => { frame = null; draw(); };
      im.src = `/api/live/${encodeURIComponent(select.value)}.jpg?t=${Date.now()}`;
    }
    canvas.addEventListener("click", (e) => {
      const r = canvas.getBoundingClientRect();
      const x = Math.min(Math.max((e.clientX - r.left) / r.width, 0), 1);
      const y = Math.min(Math.max((e.clientY - r.top) / r.height, 0), 1);
      points.push([+x.toFixed(4), +y.toFixed(4)]);
      draw();
    });
    $("zone-undo").addEventListener("click", () => { points.pop(); draw(); });
    $("zone-clear").addEventListener("click", () => { points = []; draw(); });
    $("zone-save").addEventListener("click", async () => {
      try {
        const r = await api("/api/zone", { method: "POST", json: { points } });
        points = r.points; draw();
        toast("Restricted zone saved", "ok");
      } catch (err) { toast("Error: " + err.message, "error"); }
    });
    select?.addEventListener("change", loadFrame);
    api("/api/zone").then((r) => { points = r.points; draw(); });
    loadFrame();
  }
})();
