# Code-Review obacht-agent — 2026-07-17

Gesamtreview des Agent-Repos (~15k Zeilen Go, 89 Dateien) über 8 parallele Finder-Angles,
Fokus auf die security-kritischen Pfade (Signed Mutations, Compose-Allowlist, IPC, Ingress).
Branch: `fix/compose-allowlist-escapes`. Die Top-Findings sind direkt am Code verifiziert
(CONFIRMED); die übrigen sind plausibel und reproduzierbar beschrieben.

Gesamtbild: Die Krypto-/Signed-Mutation-Schicht ist sorgfältig gebaut und **fail-closed**
(der Agent verifiziert gegen seine *eigene* JCS-Ausgabe, Kanonisierungs-Divergenzen führen
zu Deny, nie zu False-Accept; Replay/Nonce/Ordering korrekt). Die realen Lücken liegen an den
Rändern: die Compose-Allowlist läuft **vor** der Docker-Interpolation, mehrere Confused-Deputy-
Pfade (Config → Host-Env, Config → Caddyfile), und eine Reihe von Concurrency-/State-Bugs im
Reconciler und WS-Client.

---

## CRITICAL — Sandbox-Escape / Confined-Deputy

### 1. Compose-Allowlist läuft vor der `${VAR}`-Interpolation → Host-Bind-Mount-Escape
`internal/runtime/compose/compose.go:272` (schreibt `.env`) → `:534` (`--env-file`), Validierung `:651`

Der jüngste Commit `de288c5` hat top-level `volumes`/`networks` und den `env_file`-Service-Key
geschlossen — aber der **`.env`-Textarea-Pfad** bleibt offen. Ablauf:

1. `ValidateComposeBody(body)` läuft auf dem **un-interpolierten** Body (`:651`).
2. Danach wird `spec.EnvFile` (User-„env"-Textarea) roh nach `.env` geschrieben (`:272`).
3. `docker compose up --env-file .env` (`:534`) macht **danach** die `${VAR}`-Interpolation.
4. `findUnsubstituted` (`:719`) fängt nur `${secret.x}`/`${cfg.x}`, **nicht** generische `${VAR}`.

**Exploit** (custom-docker-composition):
```yaml
volumes: { "${HV}": }          # null-Def → validateTopLevelDefs continue → declaredVolumes["${HV}"]=true
services:
  app:
    image: alpine
    volumes: ["${HV}:/host"]    # source "${HV}" gilt als "declared" → passt
```
`.env`: `HV=/` → nach Interpolation `["/:/host"]` = **Host-Root rw in den Container gemountet**.
Vollständiger Sandbox-Escape, genau die Klasse, die `de288c5` schließen wollte.

**Fix:** Nach der Substitution jede verbleibende `${...}`-Sequenz im Body ablehnen (nicht nur
`secret`/`cfg`), ODER die `.env`-Werte selbst vor dem Schreiben interpolieren und den bereits
interpolierten Body validieren, ODER `--env-file` für custom Bodies ganz streichen.

### 2. Untrusted Config `${env.X}` erreicht die Host-Umgebung des Agenten
`internal/manifest/materialize.go:558-573` (Re-Scan-Loop) + `:587` (`os.LookupEnv`)

`substituter.string()` iteriert bis zu 5×, damit verschachtelte Placeholder auflösen. Dadurch
wird ein **User-Config-Wert**, der selbst `${env.SECRET}` enthält, im nächsten Durchlauf über
`os.LookupEnv` aus der **Agent-Host-Umgebung** expandiert.

**Exploit:** User setzt ein configSchema-Feld (z. B. `cfg.name`) auf den Literalstring
`${env.OBACHT_DB_PASSWORD}`. Pass 1 ersetzt `${cfg.name}` → dieser String; Pass 2 matcht
`env.`-Prefix → Host-Env-Wert landet in Container-env/labels/command/image. Confused-Deputy-
Exfiltration beliebiger Agent-Env-Variablen über normale Templates (nicht nur custom-compose).

**Fix:** `${env.*}` nur aus **Template-gelieferten** Strings auflösen, niemals aus expandierten
`cfg`-Werten. Am saubersten: `env`/`cfg`/`secret` in **einem** Pass ohne Re-Scan des Outputs
auflösen, oder cfg-Werte nach der Ersetzung nicht erneut nach Placeholdern durchsuchen.

### 3. `security_opt` / `user` / `sysctls` in der Allowlist ohne Wertvalidierung
`internal/runtime/compose/allowlist.go:27`

`privileged`, `cap_add`, `devices`, `userns_mode` sind verboten — aber `security_opt`, `user`
und `sysctls` sind **ohne Value-Check** erlaubt. Ein Body kann damit die Confinement, die die
Härtung schützt, direkt wieder aufheben:
```yaml
security_opt: ["seccomp=unconfined", "apparmor=unconfined", "no-new-privileges=false"]
user: "0:0"        # root-in-container; owned shared named-volume data als root
```
Aus jedem Kernel-/Runtime-CVE wird so ein Host-Breakout, ohne je die privileged/cap-Gates zu
berühren. **Fix:** `security_opt` auf eine Whitelist (z. B. nur `no-new-privileges=true`)
einschränken, `user` auf Nicht-Root erzwingen, `sysctls` streichen oder auf `net.*`-Safe-Set
begrenzen.

### 4. IPC-Admin-Endpunkte offen für jeden Peer mit uid 0 (Zweitstufe, standalone nicht erreichbar)
`internal/ipc/server.go:100`

`adminGuard` erlaubt `uid == 0`. Der Agent läuft selbst als root (`deploy/obacht-agent.service:13`,
`User=root`), also ist `selfUID=0` und der Check bedeutet effektiv „nur root darf Admin".

**Reachability-Korrektur nach Verifikation:** Ein Template-Container erreicht den IPC-Socket
(mode 0660, `/run/obacht/...`) normalerweise **nicht** — die Allowlist verbietet Host-Bind-Mounts,
also kann ein Template den Socket nicht selbst einbinden, und ein Auto-Mount durch den Agenten
existiert nicht. Damit ist dies **kein eigenständiger Exploit**, sondern eine **Zweitstufe**:
Erst wenn #1 (Compose-Escape) einen Container auf den Host bringt, wird der Socket als root
erreichbar → voller `/v1/admin/*` (Secrets aller Instances, User-Keys pinnen). Zusätzlich: ohne
`SO_PEERCRED` liefert `peerUID` `-1` und die uid-Prüfung entfällt (`peercred_other.go:11`).

**Fix:** Der naive „strikt selfUID"-Fix hilft nicht (selfUID IST 0). Echter Fix = userns-Remap für
Template-Container (Container-root ≠ Host-root) — größerer Umbau, separat zu #1 zu behandeln. Kurzfristig
zählt: #1 schließen, dann ist #4 nicht erreichbar.

---

## HIGH — Correctness / Verfügbarkeit

### 5. wsclient `Emit` — Nil-Deref-Panic bei gleichzeitigem Disconnect (crasht den Agenten)
`internal/api/wsclient.go:135` — CONFIRMED

`Emit` prüft `c.conn != nil` unter Lock (`:117-120`), gibt den Lock frei zum Marshallen, nimmt
ihn wieder und liest `c.conn` **erneut ohne Nil-Check** (`:135`). Setzt `disconnect()` dazwischen
`c.conn=nil`, panict `c.conn.WriteMessage` → der gesamte Agent-Daemon stirbt (IPC + Reconcile weg).
Auslöser: Install fertig → `pushObserved` → `Emit` genau während eines der ~15-min-WS-Resets.
**Fix:** die lokale `conn`-Variable verwenden (schon oben gecaptured), nicht `c.conn` neu lesen.

### 6. `obachtctl instance set-state` schlägt über IPC immer fehl
`cmd/obachtctl/main.go:357` — CONFIRMED

`body, _ := json.Marshal(map[string]string{"state": ...})` erzeugt `[]byte`; `doIPC` marshallt
den Body ein **zweites** Mal (`:101`). `json.Marshal([]byte)` liefert einen base64-JSON-String
(`"eyJzdGF0ZSI6...=="`). Der Server dekodiert in `struct{State string}` → 400. Alle anderen
Caller übergeben eine `map`/`nil`; nur set-state ist betroffen → **Stop/Start ist über die CLI
komplett kaputt.** **Fix:** die `map` direkt an `doIPC` geben (nicht vor-marshallen).

### 7. Signed `domain.upsert` meldet OK trotz fehlgeschlagenem Caddy-Reload
`internal/sync/signed_mutation.go:141` — CONFIRMED

`_ = s.ingress.Reload(ctx)` verschluckt den Fehler; `dispatchSignedMutation` gibt `nil` zurück
und der User bekommt `signed_mutation_result ok=true`. Ist die Caddy-Config ungültig oder der
Reload-Socket belegt, ist die Domain „grün" gemeldet, während Caddy weiter die alte Config fährt.
**Fix:** Reload-Fehler propagieren und die Mutation als failed melden.

### 8. Orphan-GC rennt gegen den seriellen Apply-Worker
`internal/reconciler/loop.go:489` (Container) / `:514` (Compose)

Die Orphan-Bereinigung ist **nicht** durch `workerBusyWith` geschützt. Wird eine Instance-Zeile
per IPC hart gelöscht, während der Worker mitten in `docker.Apply` steckt (langer Pull, Container
schon erstellt), ruft ein Reconcile-Pass `docker.Remove(id)` **parallel** zum laufenden Apply auf.
Beide Docker-Ops rennen auf denselben Container; danach schreibt der Worker `UpsertService`/
`SetObservedState` für die eben gelöschte Instance und reanimiert State. **Fix:** GC gegen
`workerBusyWith` gaten (wie die Apply-Pfade).

### 9. `observed_state` bleibt hängen: perpetual „installing" bzw. „stopped" nie zurückgesetzt
`internal/reconciler/loop.go:573` (installing) und `:634` (stopped-Pfad ohne `SetObservedState`)

- Transienter Docker-Fehler nach `markInstalling`: observed bleibt `installing`, der nächste Pass
  early-returnt (`:411`), der echte Fehler wird nie als `error` sichtbar. UI zeigt ewig „installing".
- Stop-Pfad (`reconcileContainerDown`) entfernt den Container, ruft aber nie `SetObservedState`;
  observed bleibt `installed`/`running` obwohl kein Container existiert — dauerhaft falscher Status.

**Fix:** in beiden Pfaden observed explizit auf `error` bzw. `stopped` setzen.

### 10. Self-Update-Signaturprüfung ist umgehbar (Signature-Stripping-Downgrade)
`install.sh:160-177` — CONFIRMED

Obwohl signierte Releases Policy sind, ist das Gate **fail-open**. Bei `SELF_UPDATE=1` mit
gesetztem `VERIFY_SUPPORT_MARKER`:
```sh
if curl -fsSL -o "$asset.minisig" "$base_url/$asset.minisig" 2>/dev/null; then
  ... verify-release ... case 1) FATAL ;; *) WARN continuing on sha256 ;;
else
  echo "WARN: no .minisig ... continuing on sha256"   # <-- fährt trotzdem fort
fi
```
Fehlt die `.minisig` (ein kompromittierter Release-Publisher **lässt die Signatur einfach weg**),
greift der `else`-Zweig und installiert weiter — abgesichert nur durch `sha256`, das aus **derselben**
GitHub-Release-Quelle wie das Tarball kommt und daher gegen eine Release-Host-Kompromittierung
nichts bringt. Zusätzlich ist exit-code 2 (`*)`) ein Soft-Continue, d. h. auch eine
nicht-verifizierbare/abgeschnittene Signatur downgradet auf sha256. Das hebelt die gesamte
Offline-Signatur-Verteidigung aus (vgl. Memory-Regel „always sign agent releases").

**Fix:** Sobald der Support-Marker existiert, „keine `.minisig`" **und** exit-code 2 als **fatal**
behandeln (`exit 1`). sha256 aus derselben Quelle darf kein akzeptierter Fallback für ein
Self-Update sein.

### 11. Caddyfile-Injection über un-escapte Upstream/PathPrefix/ServiceName
`internal/ingress/caddy.go:392` (`svc.Target`), `:390` (`bind.PathPrefix`), `:373` (`ServiceName`)

Nur die Domain wird über `isValidDomain` validiert. `svc.Target`, `bind.PathPrefix` und
`bind.ServiceName` fließen roh in den Caddyfile-Template-String (`reverse_proxy %s`, `handle %s*`,
quoted `respond "..."`). Enthält einer davon Whitespace/Braces/Newlines/Quotes, lassen sich
Caddy-Direktiven oder ganze Site-Blocks injizieren (Routing kapern, TLS abschalten, auf interne
Hosts proxien). Inkonsistent: der Fehler-Pfad `:386` escaped via `escape()`, der Erfolgs-Pfad nicht.
**Fix:** alle in den Caddyfile interpolierten Felder durch `escape()` bzw. strikte Validierung.

---

## MEDIUM — Härtung / Robustheit

| # | Datei:Zeile | Befund | Failure |
|---|---|---|---|
| 11 | `internal/files/handler.go:177` | `safeJoin` prüft nur lexikalisch (Clean+HasPrefix), löst keine Symlinks auf — widerspricht dem Package-Doc | Template-Container legt Symlink `link -> /etc` im Webroot; download/upload/delete folgt ihm → Host-FS-Zugriff |
| 12 | `internal/ipc/server.go:917` | `adminSetSystemSetting` dekodiert `r.Body` ohne `io.LimitReader` (alle Geschwister cappen 1<<10..1<<20) | Multi-GB-Body → OOM auf dem Pi |
| 13 | `internal/api/wsclient.go:163` | Reconnect-Backoff wird nach erfolgreicher Session nie auf 1s zurückgesetzt, ratcht dauerhaft auf 30s | Nach ~5 WS-Resets garantiert ~30s Offline-Fenster pro Reset → Signed Mutations/Domain-Claims failen „device offline" |
| 14 | `internal/api/wsclient.go:135` | Kein Write-Deadline; `WriteMessage` auf half-open Conn blockt ewig unter `mu` | Toter TCP-Pfad → Emit/Pong blockieren, Client erkennt den toten Peer nie, reconnectet nie |
| 15 | `internal/ipc/server.go:788` | `redactInstanceConfig` gibt bei JSON-Parse-Fehler die Rohbytes zurück, `instanceToMap` setzt trotzdem `sanitized:true` | Leicht kaputtes ConfigJSON mit `DB_PASSWORD=...` → Klartext-Secret über `obachtctl instance get`, als „sanitized" getarnt |
| 16 | `internal/sync/signed_mutation.go:95-118` | Nonce wird in `Verify` verbraucht, bevor `dispatch` läuft | Verifizierte, aber transient fehlgeschlagene Mutation → Nonce verbrannt, identisches Envelope als Replay abgelehnt, Op nie ausführbar |
| 17 | `internal/signedmut/envelope.go:191` | `m.Exp-m.Iat > maxLifetime` — Integer-Overflow nahe `MaxInt64` | Exp≈MaxInt64 + stark negatives Iat → effektiv nie-ablaufende signierte Mutation (nur durch Key-Holder erreichbar) |
| 18 | `internal/store/template_secrets.go:91` | `randString` nutzt `buf[bi]%62` → Modulo-Bias trotz Kommentar; kein Rejection-Sampling | Generierte Secrets/Passwörter minimal ungleichverteilt (Bytes 0-7 leicht häufiger) |
| 19 | `internal/manifest/materialize.go:394` | `env_file` aus User-Config-Wert ohne Pfad-Validierung; `:256` Volume-`source` über `subst.string` ohne Traversal-Check | User setzt Wert auf `/etc/...` bzw. `../../` → Agent liest beliebige Host-Datei als Container-env / bindet Host-Pfad |
| 20 | `internal/redact/redact.go:36` | Redaction-Patterns matchen `PASSWORD`/`PASSWD`, aber nicht den Stamm `PASS` (`DB_PASS`, `SMTP_PASS`), auch nicht `CREDENTIAL`/`PASSPHRASE`/`AUTH` | Latent: künftige env-Telemetrie leakt gängige Secret-Keys still — Package ist als Safe-Default gedacht |
| 21 | `internal/store/locks.go:24` | `TryAcquireLock` non-transaktionales SELECT-then-INSERT, jeder Insert-Fehler → `ErrLockHeld` | Ohne UNIQUE-Constraint auf `group_name` halten zwei Instances denselben Exclusivity-Lock; echte DB-Fehler als „lock held" maskiert |
| 22 | `internal/store/secrets.go:16` | `EnsureInstanceSecret` → `INSERT ... ON CONFLICT DO UPDATE` überschreibt bei Race das bestehende Secret | Zwei Reconcile-Pässe → zweiter überschreibt, Config-Hash/Auth-Token mitten im Reconcile invalidiert |
| 23 | `internal/ipc/server.go:421` / `signed_mutation.go:200` | `adminSetInstanceState`/`instance.set_state` machen non-transaktionales GetInstance→mutate→Upsert der ganzen Zeile | Gleichzeitiger Upsert aus anderem Pfad → Lost Update, gerade angewandte Rekonfiguration still verworfen |
| 24 | `internal/logs/handler.go:141` / `internal/ipc/server.go:1176` | Docker-`name`-Filter `^obacht-<id>$` interpoliert `id` roh; `isSafeArg` erlaubt `.` (Regex-Metachar) | id `a.c` → `^obacht-a.c$` matcht `obacht-axc` → Logs des falschen Containers |
| 25 | `internal/files/handler.go:195` | `opList`/`opMkdir` rufen `os.MkdirAll` — eine „read"-Operation mutiert das FS | `list path=does/not/exist` legt Verzeichnisse an statt not-found; Inode-Clutter |
| 26 | `internal/audit/writer.go:130,154` | DB-Insert und File-Append nicht atomar, kein per-Entry-fsync | Crash zwischen beiden → Seq-Lücke zwischen SQLite und (als kanonisch dokumentiertem) JSONL; Tamper-Check-Fehlalarm |
| 27 | `internal/diskcheck/diskcheck.go:47` | `FreeBytes = f_bavail * f_bsize`, verfügbare Blöcke sind aber in `f_frsize`-Einheiten definiert | Auf FS mit `f_bsize != f_frsize` falsch skalierter Free-Wert → 2-GiB-Guard blockt/erlaubt falsch |
| 28 | `internal/config/config.go:50` | Device-JWT (`AuthToken`) im Klartext-YAML, ohne erzwungenen File-Mode | Jeder lokale Leser/Backup bekommt langlebiges Device-Credential |
| 29 | `internal/reconciler/loop.go:275` + `docker.go:79` (kein Pull-Timeout) | Apply-Worker ist strikt seriell und Image-Pulls haben kein Gesamt-Timeout → Head-of-Line-Blocking | Ein black-hole-Pull (genau das bekannte Hotspot-/MTU-Blackhole-Szenario) TCP-stallt ohne Reset; `applyOne` kehrt nie zurück, **alle** anderen Installs/Config-Updates hängen bis Agent-Neustart. Braucht ctx-Deadline/Watchdog |
| 30 | `docker.go:637` + `compose.go:309` | `maxPct`-High-Water-Mark ist pro Image gescoped; bei Multi-Image-Bundles startet der Balken je Image bei 0 | Progress-Bar springt sichtbar 100%→4%→100% pro Image — verletzt die dokumentierte Monotonie-Invariante |
| 31 | `cmd/obacht-agent/main.go:246` | SIGTERM kehrt sofort bei `<-ctx.Done()` zurück, deferred `st.Close()` läuft, ohne auf Worker/Syncer zu warten | Shutdown mitten im Install → Worker schreibt `SetObservedState` gegen bereits geschlossene DB („database is closed", torn write); heilt per SSOT beim nächsten Boot |
| 32 | `internal/runtime/compose/compose.go:310` | Pre-Pull-Loop `break`t beim ersten Image-Fehler → Images 2..n bekommen keine Progress-Events | Ist Image1 kurz unauflösbar, fällt das ganze Bundle still auf progress-loses `up -d` zurück; `continue` statt `break` würde den Rest erhalten |

Positiv bestätigt am jüngsten Diff: der Worker-Kick/Drain-Pattern (`workKick` buffered-1 + innerer len-Recheck) ist deadlock-frei, `workPending`-Dedup korrekt, `pullResp.Body` sauber geschlossen, und der Compose-`--project-name` neutralisiert das top-level `name`-Feld.

---

## Nicht beanstandet (geprüft, solide)
- Signed-Mutation-Kern: Pinned-Key-Gate (Envelope-Pubkey nur akzeptiert bei Byte-Match eines lokal
  gepinnten Keys), ed25519-Längen/Empty/Truncated-Checks, Verify→Device→Time→Replay-Ordering,
  atomarer `INSERT OR IGNORE`-Nonce-Store mit Retention > maxLifetime, JCS-Escaping bewusst
  JS-kompatibel, UTF-8-Validierung vor UTF-16-Key-Sort, Trailing-Garbage-Reject. Alle Fehlerpfade
  fail-closed.
- `internal/logs/handler.go`: argv statt Shell, striktes `isSafeArg`, bounded tail (1-5000),
  15s-Context-Timeout, keine Goroutine-/Handle-Leaks (abgesehen vom `.`-Metachar unter #24).

---

## Empfohlene Reihenfolge
1. **#1 + #3** zusammen (Compose-Escape schließen — die Härtung `de288c5` ist unvollständig).
2. **#2** (Config→Host-Env-Exfiltration; betrifft alle Templates).
3. **#10** (Self-Update-Signature-Stripping — Supply-Chain-Gate, einzeiliger `install.sh`-Fix).
4. **#5, #6, #7** (harte Correctness-Bugs, klein zu fixen).
5. **#4** (Admin-uid-Gate) + #9 (State-Stuck, UI-Verwirrung).
6. Rest nach Kapazität.
