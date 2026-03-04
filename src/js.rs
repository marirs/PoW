/// Embedded JavaScript solver for multi-round PoW.
///
/// This is designed to be included in a `<script>` tag on the login page.
/// It expects the following DOM elements:
/// - `#pow_chain_id` — hidden input with chain ID
/// - `#pow_prefix` — hidden input with current round prefix
/// - `#pow_difficulty` — template variable (integer)
/// - `#pow_total_rounds` — template variable (integer)
/// - `#pow_nonce` — hidden input where final "done" marker is set
/// - `#pow-status` — status text shown while solving
/// - `#pow-ready` — text shown when done
/// - `#login-btn` — submit button (disabled until done)
///
/// The solver POSTs each round solution to `/pow/submit` and receives
/// the next round's prefix, or a completion signal.
pub const SOLVER_JS: &str = r##"
(function(){
  var chainId = document.getElementById('pow_chain_id').value;
  var prefix = document.getElementById('pow_prefix').value;
  var difficulty = parseInt(document.getElementById('pow_difficulty').value, 10);
  var totalRounds = parseInt(document.getElementById('pow_total_rounds').value, 10);
  var currentRound = 0;

  if (!chainId || !prefix || difficulty <= 0) {
    document.getElementById('login-btn').disabled = false;
    document.getElementById('pow-status').style.display = 'none';
    document.getElementById('pow-ready').style.display = '';
    return;
  }

  function hexFromBuf(buf) {
    var a = new Uint8Array(buf), h = '';
    for (var i = 0; i < a.length; i++) h += ('0' + a[i].toString(16)).slice(-2);
    return h;
  }

  function leadingZeroBits(h) {
    var b = 0;
    for (var i = 0; i < h.length; i++) {
      var v = parseInt(h[i], 16);
      if (v === 0) { b += 4; } else { if (v < 2) b += 3; else if (v < 4) b += 2; else if (v < 8) b += 1; break; }
    }
    return b;
  }

  function randomHexNonce() {
    var a = new Uint8Array(8);
    crypto.getRandomValues(a);
    return hexFromBuf(a.buffer);
  }

  function updateStatus() {
    var el = document.getElementById('pow-status');
    if (el) el.innerHTML =
      '<svg width="14" height="14" viewBox="0 0 24 24" style="animation:spin 1s linear infinite" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 2v4m0 12v4m-7.07-15.07l2.83 2.83m8.48 8.48l2.83 2.83M2 12h4m12 0h4M4.93 19.07l2.83-2.83m8.48-8.48l2.83-2.83"/></svg> ' +
      'Verifying (' + (currentRound + 1) + '/' + totalRounds + ')…';
  }

  function solveRound(pfx, diff, onFound) {
    var found = false;
    var nonce = 0;

    function solveBatch() {
      if (found) return;
      var batch = 2000;
      var promises = [];
      for (var i = 0; i < batch; i++) {
        var nonceHex = ('0000000000000000' + (nonce + i).toString(16)).slice(-16);
        var msg = pfx + nonceHex;
        var enc = new TextEncoder().encode(msg);
        promises.push(crypto.subtle.digest('SHA-256', enc).then((function(nh){
          return function(buf) {
            if (!found && leadingZeroBits(hexFromBuf(buf)) >= diff) {
              found = true;
              onFound(nh);
            }
          };
        })(('0000000000000000' + (nonce + i).toString(16)).slice(-16))));
      }
      nonce += batch;
      Promise.all(promises).then(function() {
        if (!found) setTimeout(solveBatch, 0);
      });
    }
    solveBatch();
  }

  function submitRound(nonceHex) {
    fetch('/pow/submit', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({ chain_id: chainId, nonce: nonceHex })
    })
    .then(function(r) { return r.json(); })
    .then(function(data) {
      if (data.status === 'complete') {
        document.getElementById('pow_nonce').value = 'complete';
        document.getElementById('login-btn').disabled = false;
        document.getElementById('pow-status').style.display = 'none';
        document.getElementById('pow-ready').style.display = '';
      } else if (data.status === 'next_round') {
        currentRound = data.round;
        prefix = data.prefix;
        difficulty = data.difficulty;
        updateStatus();
        solveRound(prefix, difficulty, submitRound);
      } else {
        document.getElementById('pow-status').textContent = 'Verification failed. Please reload.';
      }
    })
    .catch(function() {
      document.getElementById('pow-status').textContent = 'Network error. Please reload.';
    });
  }

  updateStatus();
  solveRound(prefix, difficulty, submitRound);
})();
"##;
