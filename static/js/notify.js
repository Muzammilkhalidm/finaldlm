/* notify.js - employee notification popup + sound + live numbered counters.
   Polls the server; every new admin announcement / task / reply / warning opens a popup with numbered
   items and plays the ringtone. Ringtone file: static/sounds/notify.mp3 (or .ogg/.m4a/.wav) - see /notification-sound */
(function () {
    'use strict';
    var meta = document.querySelector('meta[name="csrf-token"]');
    var csrf = meta ? meta.content : '';
    var root = document.getElementById('notify-root');
    if (!root) return;

    var KIND_LABEL = { announcement: 'Announcement', task: 'Task', message: 'Message from Admin', warning: 'Warning' };
    var baseTitle = document.title;
    var shown = [];                // notifications currently inside the popup
    var audio = new Audio('/notification-sound');
    audio.preload = 'auto';
    var soundBlocked = false;

    function playSound() {
        try {
            audio.currentTime = 0;
            var p = audio.play();
            if (p && p.catch) p.catch(function () { soundBlocked = true; });
        } catch (e) { soundBlocked = true; }
    }
    // Browsers block sound until the user has touched the page once; play it as soon as they do.
    ['click', 'keydown', 'touchstart'].forEach(function (ev) {
        window.addEventListener(ev, function () {
            if (soundBlocked) { soundBlocked = false; playSound(); }
        }, { passive: true });
    });

    function el(tag, cls, text) {
        var n = document.createElement(tag);
        if (cls) n.className = cls;
        if (text != null) n.textContent = text;
        return n;
    }

    function updateCounts(counts) {
        document.querySelectorAll('[data-count-kind]').forEach(function (b) {
            var n = counts[b.getAttribute('data-count-kind')] || 0;
            b.textContent = n;
            b.hidden = n === 0;
        });
        document.title = (counts.total ? '(' + counts.total + ') ' : '') + baseTitle;
    }

    function render() {
        root.textContent = '';
        if (!shown.length) return;
        var back = el('div', 'popup-backdrop');
        var box = el('div', 'popup');
        box.setAttribute('role', 'alertdialog');
        box.setAttribute('aria-modal', 'true');
        var head = el('div', 'popup-head');
        head.appendChild(el('span', 'num', shown.length));
        head.appendChild(el('h3', null, shown.length === 1 ? 'New message from Admin' : 'New messages from Admin'));
        var list = el('div', 'popup-list');
        shown.forEach(function (n, i) {
            var item = el('div', 'popup-item ' + n.kind);
            item.appendChild(el('span', 'num', i + 1));
            var body = el('div');
            body.appendChild(el('h4', null, n.title));
            if (n.body) body.appendChild(el('p', null, n.body));
            body.appendChild(el('small', null, (KIND_LABEL[n.kind] || 'Notice') + ' · ' + (n.created_at || '').slice(0, 16)));
            item.appendChild(body);
            list.appendChild(item);
        });
        var foot = el('div', 'popup-foot');
        var ok = el('button', 'btn small', 'OK');
        ok.type = 'button';
        ok.addEventListener('click', dismiss);
        foot.appendChild(ok);
        if (shown[0].url) {
            var open = el('a', 'btn secondary small', 'Open');
            open.href = shown[0].url;
            foot.insertBefore(open, ok);
        }
        box.appendChild(head); box.appendChild(list); box.appendChild(foot);
        back.appendChild(box);
        root.appendChild(back);
        ok.focus();
    }

    function dismiss() {
        var ids = shown.map(function (n) { return n.id; });
        shown = [];
        render();
        fetch('/api/notifications/read', {
            method: 'POST', credentials: 'same-origin',
            headers: { 'Content-Type': 'application/json', 'X-CSRFToken': csrf },
            body: JSON.stringify({ ids: ids })
        }).then(function (r) { return r.json(); }).then(function (d) { if (d.counts) updateCounts(d.counts); })
          .catch(function () {});
    }
    document.addEventListener('keydown', function (e) { if (e.key === 'Escape' && shown.length) dismiss(); });

    function poll() {
        fetch('/api/notifications/poll', { credentials: 'same-origin' })
            .then(function (r) { return r.ok ? r.json() : null; })
            .then(function (d) {
                if (!d || !d.ok) return;
                updateCounts(d.counts);
                if (d.popups && d.popups.length) {
                    shown = shown.concat(d.popups);
                    render();
                    playSound();
                }
            }).catch(function () {});
    }
    poll();
    setInterval(poll, 15000);
    document.addEventListener('visibilitychange', function () { if (!document.hidden) poll(); });
})();
