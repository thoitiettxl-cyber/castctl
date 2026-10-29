# Native login bundle analysis — research note (PARKED)

Source: read-only public bundle analysis, 2026-10-29 (original report kept at `~/workspace/tmp/native-bundle-analysis/report.md`).
Verdict: PARTIAL. Status: PARKED by Boss decision. Revisit ONLY if the user later supplies a redacted HAR.
The no-credential probe described in the body is NOT approved and must never run.
Scratch chunk copies are NOT in the repo (they remain under `~/workspace/tmp/native-bundle-analysis/chunks/`).
The Vietnamese body below is copied verbatim.

---

# Phân tích bundle cho native login muse.ai — READ-ONLY, không credential, không POST

Ngày: 2026-10-29. Phạm vi: phân tích tĩnh bundle JS public của web app muse.ai
để xác định contract của luồng login native (identifier → mã → verify).
KHÔNG code, KHÔNG sửa file nào trong worktree, KHÔNG probe credential,
KHÔNG login attempt, KHÔNG POST nào được gửi, KHÔNG cookie nào được gửi
kèm fetch, KHÔNG auth header nào được gửi. Tất cả fetch đều là GET public,
không cookie, timeout 30–60s. Chunk đã tải lưu tại
`~/workspace/tmp/native-bundle-analysis/chunks/` (44 file, 2.466.277 byte,
tất cả HTTP 200). Minified locals được trích đúng tên trong bundle
(`uQ`, `fw`, `fN`, `a_`, `oi`, `tR`) — không phải tên gốc của Meta.

Nguồn đọc trước: `~/workspace/tmp/muse-login-research/report.md` (prior
findings — relay infeasible, device-code none, cookie `hatch_native_auth_*`,
không endpoint login trong code 0.6.1), `docs/PROTOCOL.md`
(derive-client workflow) và `gateway.py` (chuỗi auth sau login:
GET /api/session → POST /api/auth/check → POST /api/hatch/token → Noise WS)
trong `~/workspace/tmp/goport-v061/`. Báo cáo này chỉ bổ sung phần bundle;
không lặp lại các kết luận đó trừ khi cần nối mạch.

## 0. Fetch log (mọi URL đã fetch — GET-only)

| # | Fetch | Kết quả |
|---|---|---|
| 1 | `browser.open https://muse.ai/` | Trang marketing (bản crawl). Không chunk URL, không link login trong text trích xuất — `browser.open` lược `<script>`, nên phải đọc HTML thô (mục 2) mới liệt kê được chunk. |
| 2 | `curl GET https://muse.ai/` (không cookie) | **307** → `Location: https://auth.muse.ai/aymh/?origin=https%3A%2F%2Fmuse.ai`. Header CSP: `frame-ancestors 'self'`, `form-action 'self'`, `connect-src` gồm `*.facebook.com *.instagram.com *.meta.ai`, `wss://gateway.meta.ai`, `wss://edge-chat.meta.ai`; `Server: Vercel`. |
| 3 | `curl GET https://auth.muse.ai/aymh/?origin=https%3A%2F%2Fmuse.ai` (không cookie) | **302** → `Location: https://muse.ai/?aymh_complete=1`, body rỗng, **không `Set-Cookie`**. Request không cookie bị đẩy về — app auth cần cookie/JS, không phục vụ nội dung cho client trần. |
| 4 | `curl GET https://muse.ai/?aymh_complete=1` (không cookie) | **200**, 81.165 byte, app shell Next.js, 44 chunk JS (tên hash + `?dpl=dpl_CvYcjR5mT6dcSTSEbkUiVyBh3pnx`). |
| 5 | `curl GET` 44 chunk `/_next/static/chunks/*.js` (không cookie) | Tất cả 200, tổng 2.466.277 byte, lưu tại `chunks/`. Chunk chính: `3nweh9n_x4ey9.js` (394.163 byte, native auth client), `0jqnecgcbkz6s.js` (22.324 byte, checkpoint/OIDC client), `1-73x3hxlu162.js` (cookie definitions, gồm `datr` 730 ngày HttpOnly). |
| 6 | `browser.open https://auth.muse.ai/` | **404** — khớp finding của prior report. Không fetch lại (không retry input cũ). |
| 7 | `browser.search` ×2 | `#PWD_BROWSER` + AYMH/login (xem §2.4, §3.4). Chỉ cho góc prior report chưa cover. |

Giới hạn phương pháp (quan trọng): bundle của app `auth.muse.ai` KHÔNG
fetch được khi không có cookie (302 về, body rỗng). Mọi phát hiện dưới đây
đến từ bundle của app `muse.ai` — và bundle này CÓ chứa toàn bộ client
login native (AYMH cards, native auth, provider SSO, checkpoint). Các
chunk lazy-load theo route (vd. dynamic import `e.A(291462)` cho libsodium)
không nằm trong 44 file này; contract trong các chunk đó là chưa biết.

## 1. Endpoint inventory (từ bundle; base `https://muse.ai` trừ khi ghi khác)

Quy ước contract: COMPLETE = đủ method + path + body + header + response
để replay; PARTIAL = thiếu ≥1 mảnh (ghi rõ mảnh nào); ABSENT = chỉ thấy
tên, không thấy contract. Mọi POST native đều JSON, browser tự gửi cookie
same-origin (fetch không set `credentials` tường minh trong code native;
CLI replay phải tự quản Cookie header + jar). Response lỗi dùng taxonomy
`type` ở §3.3.

### 1.1 Native auth — `POST /api/auth/native/<action>` (`fN(e)` = `` `/api/auth/native${e}` ``)

| Action | Body (field names, như trong code) | Response / outcome | Contract |
|---|---|---|---|
| `GET /bootstrap?resume_provider_completion=1` | — (GET, header `J()` only, `cache:"no-store"`) | `{csrf_token: string (bắt buộc), flow_state, ...}`; dùng cho cả resume provider SSO | PARTIAL — các field khác ngoài `csrf_token`/`flow_state` chưa parse hết |
| `POST /start` | `"{}"` | `{csrf_token, flow_state, password_encryption?: {key_id, public_key}}`; nhánh `flow_state==="new"` mới gọi | PARTIAL — token CSRF nào seed cho lần `/start` đầu chưa resolve (xem §2.1) |
| `POST /restart` | `"{}"` | `{flow_state:"started", csrf_token}` (restart sau `authFlowExpired`/`csrfFailed`) | COMPLETE (shape) |
| `POST /send-otp` | `{contact_point: string.trim(), region?: string}` (`region` từ `Intl.Locale(navigator.language).region`) | `{masked_contact?, password_login_available?, registration_state?}`; lỗi 403 `regionNotSupported` | PARTIAL — full response shape chưa trích hết |
| `POST /resend-otp` | `{}` | `{registration_state?: "password_required", password_login_available?}` | PARTIAL |
| `POST /confirm-otp` | `{otp_code: string (6 số, từ state input), ...submitAnswer(), return_to?}` | outcome: `redirected` \| `twoFactor` \| `reactivation` \| `completed` (+ `auth_meta_session`) \| error | PARTIAL — `submitAnswer()` chưa resolve (§2.3) |
| `POST /confirm-password` | `{password: "#PWD_BROWSER:5:..." (uQ, §2.4), ...submitAnswer(), return_to?}` | như trên | PARTIAL — crypto COMPLETE, `submitAnswer()` chưa resolve |
| `POST /two-factor` | `{method_id, code, ...answerField(), return_to?}` | outcome như trên; methods gồm TOTP + SMS (xem §3.1) | PARTIAL — `answerField()` chưa resolve |
| `POST /two-factor-send-code` | (chưa trích được body) | gửi lại mã 2FA | ABSENT (chỉ thấy tên action) |
| `POST /select-account` | `{account_id, ...answerField(), return_to?}` | outcome như trên | PARTIAL — `answerField()` chưa resolve |
| `POST /saved-account-otp` | `{account_cuid}` | outcome như trên | PARTIAL — response shape chưa trích hết |
| `POST /one-tap-login` | (args chưa trích hết; có restart-on-expiry, trả `restartedCsrfToken`) | outcome `restartFailed` nếu không restart được | PARTIAL |
| `POST /aymh-cards` | `{handle}` + header `X-Hatch-CSRF-Token` | `{accounts, cards, supersededSavedAccountIds, tos, hidesTosClause}` | PARTIAL |
| `POST /register-completion` | `{date_of_birth, first_name?, last_name?, tos_content_version, password?, ...answerField(), return_to?}` | outcome như trên | PARTIAL |
| `POST /register-completion-linked` | `{...answerField(), return_to?}` | outcome như trên | PARTIAL |
| `POST /remove-saved-account` | `{account_cuid}` | — | PARTIAL |
| `POST /remove-cross-app-account` | (chưa trích được body) | — | ABSENT (chỉ thấy tên) |
| `POST /recovery-start` | `{contact_point?}` | — | PARTIAL |
| `POST /recovery-send-code`, `/recovery-confirm-code`, `/recovery-select-account` | (chưa trích body) | — | ABSENT (chỉ thấy tên + màn hình tương ứng) |
| `POST /recovery-complete` | `{password: "#PWD_BROWSER:5:...", logout_other_sessions, return_to?}` | — | PARTIAL |
| `POST /decline-ntp-upsell` | (body rỗng/không đáng kể) | — | COMPLETE (trivial) |

Màn hình (state machine phía client, `e_(...)`): `contact`, `otp`,
`password`, `accounts`, `select-account`, `two-factor`,
`recovery-choose-contact-point`, `recovery-code`, `recovery-select-account`,
`recovery-set-password`, `create-password`, `birthday`, `reactivation`,
`ntp-upsell`. Flow states phía server: `"new"`, `"started"`,
`"two_factor_required"`, `"completion_required"`, `"password_required"`,
`"reactivation_required"`.

### 1.2 Provider SSO / OIDC / linking

| Endpoint | Contract tìm được | Contract |
|---|---|---|
| `POST /api/auth/provider-sso/start` | `{provider, completion_id: crypto.randomUUID(), caa_reg_entry_point?}`; header `Content-Type` + `X-Hatch-Caa-Reg-Entry-Point` ở bước complete | PARTIAL |
| `POST /api/auth/provider-sso/disclosure` | `{action}` + `X-Hatch-CSRF-Token` | PARTIAL |
| `POST /api/auth/provider-sso/complete` | `{completion_id}`; response: `{frl_access_token}` HOẶC `two_factor`/`completion` states (`masked_contact`) | PARTIAL |
| `GET /api/oidc/start[?return_to=]` | Navigation (click row `frl`); preparation response phải có `action` == URL `/oidc/start` tại broker origin (mặc định `https://agent.meta.ai`, env `NEXT_PUBLIC_HATCH_PROVIDER_SSO_BROKER_ORIGIN`) + `fields` toàn string → **form POST sang broker**. Phía broker (login/checkpoint của Meta) không có trong bundle | PARTIAL — phía broker ABSENT; đây là luồng browser-form, CLI replay = POST form + theo redirect + xử lý trang của broker |
| `POST /api/auth/linking/consume` | `{frl_access_token, method}` | PARTIAL |
| `POST /api/hatch/oauth/callback`, `/api/hatch/vesta-auth/` | Chỉ thấy chuỗi tên, không thấy call site | ABSENT |

### 1.3 Checkpoint / session / cookies (client đã login hoặc đang bị checkpoint)

| Endpoint | Contract tìm được | Contract |
|---|---|---|
| `/api/auth/check` (checkpoint client) | Probe: status != 403 → `{required:false}`; 403 + JSON `{type:"checkpointRequired", checkpoint_url: string}` → redirect tới `checkpoint_url`. Method không xác nhận được từ excerpt bundle (chuỗi auth sau login trong `gateway.py` dùng POST body rỗng — đó là endpoint cùng tên dùng sau login) | PARTIAL — method cho probe chưa xác nhận |
| `POST /api/auth/checkpoint/terminate` | `{sessionBindingId}`, `credentials:"include"`, timeout 15s; 409 → `location.reload()`; fail → fallback `window.location.assign("/api/logout?sessionBindingId=...")` | PARTIAL |
| `POST /api/auth/session/reset` | `{sessionBindingId?...}`, `credentials:"include"` (nhánh logout/reset/session của checkpoint client) | PARTIAL |
| `/api/logout` | Navigation GET + POST `credentials:"include"` + query `sessionBindingId` | PARTIAL |
| `POST /api/cookies/upgrade` | `{cookies:[...]}` — client tự ghi cookie non-HttpOnly qua `document.cookie`, gửi cookie HttpOnly lên server để upgrade | PARTIAL — danh sách cookie nào được upgrade chưa trích |
| `GET /api/session`, `POST /api/auth/check`, `POST /api/hatch/token` | Chuỗi sau login, đã biết từ `gateway.py` (prior work); bundle có tham chiếu `/api/auth/check` trong checkpoint client | COMPLETE (prior work) |

### 1.4 Refresh / extend / logout khác

- **Không có endpoint refresh/extend/renew token nào trong 44 chunk**
  (grep `refresh[_-]?token|extend[_-]?session|renew[_-]?session|/refresh|/extend`
  = 0 file; chuỗi `"refresh"` duy nhất không liên quan auth). Khớp prior
  report: không cơ chế refresh — hết hạn cookie = login lại.
- Không có endpoint password riêng nào ngoài `confirm-password` /
  `recovery-complete` (password luôn qua mã hóa `uQ`, §2.4). Không có
  endpoint "login bằng Facebook/Instagram password" tách biệt — provider
  SSO đi qua broker `agent.meta.ai`.

## 2. CSRF / device / state mechanics

### 2.1 CSRF token — chuỗi đầy đủ, trừ điểm seed đầu tiên

- Mọi POST native gửi header `X-Hatch-CSRF-Token: <csrf_token>`.
- Token lấy từ response JSON: `GET /bootstrap` → `csrf_token`;
  `POST /start` → `csrf_token`; `POST /restart` → `csrf_token` mới.
  Client giữ token trong state (`ev`/`nR.current`); mọi lỗi
  `csrfFailed`/`authFlowExpired` đều đi qua restart `ay()`:
  `POST /restart {}` → `{flow_state:"started", csrf_token}` → tiếp tục
  với token mới (`restartedCsrfToken` được thread qua outcome).
- **Chưa resolve:** lần gọi `/start` đầu tiên (nhánh `flow_state==="new"`)
  dùng header `l` nào làm seed — response bootstrap có `csrf_token`
  nhưng code excerpt không cho thấy chắc chắn token đó có phải seed cho
  `/start` hay `/start` dùng một token bootstrap khác. Cần HAR (mục 5).
- Không có CSRF token nào trong HTML đã serve (`grep csrf muse-aymh.html`
  = 0): token chỉ đến qua JSON, không embed trong RSC payload.

### 2.2 Waterfall id + Caa entry point (header `oi.*`)

- `X-Hatch-Waterfall-Id` (`oi.C`): UUID do client tự sinh
  (`crypto.randomUUID()` fallback), validate `/^[A-Za-z0-9-]{8,64}$/`,
  giữ ở module-scope, gửi trên mọi POST native. Cùng id này được lưu
  trong `sessionStorage` key `hatch:auth:pending_checkpoint_handoff` =
  `{checkpointUrl, waterfallId, createdAt}` (TTL 10 phút, `6e5` ms).
  (Định nghĩa trong `chunks/0jqnecgcbkz6s.js`: export `"C"` =
  `"X-Hatch-Waterfall-Id"`, `"Q"` = `"X-Hatch-Caa-Reg-Entry-Point"`.)
- `X-Hatch-Caa-Reg-Entry-Point` (`oi.Q`): giá trị từ `oi.e()` — nguồn
  của giá trị này (entry-point marker nào, lấy từ đâu) chưa resolve
  trong chunk đã fetch. PARTIAL.
- `X-Hatch-Activation-Source`: chỉ thấy tên header (1 lần), không thấy
  call site gửi nó. PARTIAL.
- `oi.J()`: object header spread vào MỌI call native (cả `/bootstrap`
  GET) — **nội dung chưa resolve** (module `oi` nằm ngoài 44 chunk đã
  fetch hoặc được build từ hằng không literal). Đây là mảnh thiếu
  quan trọng thứ hai sau `answerField()`. PARTIAL.

### 2.3 Challenge checkbox — `answerField()` / `submitAnswer()` (MẢNH THIẾU LỚN NHẤT)

- Trên màn hình OTP/password, khi `tR.enabled`, client render component
  `oa` với props `{...tR.checkbox, step: OTP|PASSWORD, flow}`.
- Mọi POST nhạy cảm đều spread thêm field từ challenge này:
  `confirm-otp`/`confirm-password` dùng `...tR.submitAnswer()`;
  `two-factor`/`select-account`/`register-completion*` dùng
  `...tR.answerField()`; `rememberDeviceField: tR.answerField()` trong
  flow chọn phương thức 2FA. `setAnswer(!0)` sau outcome twoFactor/
  reactivation; `setAnswer(null)` + `resetChecked()` khi reset flow.
- **Bản chất chưa resolve hoàn toàn:** không có `type:"checkbox"` nào
  trong chunk chính; không có SDK captcha bên thứ ba nào trong 44 chunk
  (xem §3.4); chuỗi `"Remember this device"` + field `remember_device`
  tồn tại cùng flow. Có thể checkbox này vừa là "remember device" vừa
  là first-party human-check, hoặc hai control dùng chung state —
  phân tích tĩnh không phân biệt được. Payload shape của
  `answerField()`/`submitAnswer()` (tên field + giá trị) KHÔNG có
  trong chunk đã fetch — component `oa` nằm ở chunk lazy-load khác.
  Không replay được `confirm-otp`/`two-factor`/`select-account` cho tới
  khi biết shape này. PARTIAL, blocker.

### 2.4 Password encryption `uQ` — KHÔI PHỤC ĐẦY ĐỦ, xác nhận độc lập

Hàm `uQ(password, startObj, timestamp=nowSeconds)` trong
`chunks/3nweh9n_x4ey9.js`, khôi phục nguyên vẹn:

1. `startObj` phải có `password_encryption: {key_id: int 0–255, public_key: string}`
   (parser `fw(e)` trích đúng 2 field này, thiếu → `null` → lỗi
   "Password encryption is unavailable").
2. `publicKey`: 64 ký tự hex → 32 byte; nếu không, base64-decode.
   Phải dài đúng `crypto_box_PUBLICKEYBYTES` (32).
3. Sinh AES key ngẫu nhiên 32 byte; AES-GCM encrypt password (UTF-8),
   IV = 12 byte 0, AAD = timestamp (giây, dạng string), tag 128-bit.
4. `crypto_box_seal` (NaCl sealed box, libsodium load động `e.A(291462)`)
   seal AES key bằng public key server.
5. Envelope: `0x01 || keyId || lenLE16(sealed) || sealed || tag16 || ciphertext`,
   output: `#PWD_BROWSER:5:<timestamp>:<base64(envelope)>`.
6. Public key lấy từ đâu: response `/start` (và `/restart`?) qua `fw(o)`.

Xác nhận độc lập: tìm kiếm public cho thấy đây đúng là Facebook
`FBBrowserPasswordEncryption` / `EnvelopeEncryption` (`#PWD_BROWSER`, version
5, timestamp, base64 envelope; NaCl sealed box + AES-GCM) — HackMD
"Demistify the Facebook client-side password encryption"
(https://hackmd.io/@Ostrym/facebook-client-side-encryption) và DeepWiki
`godxgamer/enc_pass`. Việc re-implement bằng Go là khả thi
(AES-GCM stdlib + sealed box = X25519 + XSalsa20-Poly1305, vd.
`golang.org/x/crypto/nacl/box` + `SealAnonymous` tương đương) — nhưng
chỉ sau khi có `key_id`/`public_key` từ `/start` thật.

### 2.5 Cookie / device / state — những gì bundle (không) cho thấy

- `hatch_sess`: **không xuất hiện trong bất kỳ chunk nào** (grep = 0).
  Client không bao giờ đọc session cookie; nó là cookie server-set,
  browser tự gửi. CLI replay phải tự quản jar.
- `hatch_native_auth_*` (`csrf`/`temp`/`device`/`state`): **không xuất
  hiện trong bất kỳ chunk nào** (grep = 0). Tên chỉ tồn tại trong jar
  đã lưu (prior report). Không có code nào trong bundle đã fetch
  set/đọc chúng → chúng thuộc về app `auth.muse.ai` hoặc server-side,
  mà bundle của app đó không fetch được khi không cookie. Cơ chế
  obtain/use của 4 cookie này là ABSENT từ phân tích tĩnh. (Đây là lý do
  prior report đánh dấu "suy luận từ tên, CHƯA KIỂM CHỨNG" — vẫn đúng.)
- `datr`: chỉ xuất hiện trong module định nghĩa cookie
  (`chunks/1-73x3hxlu162.js`): `{name:"datr", maxAgeDays:730, httpOnly:true,
  NECESSARY_FOR_GDPR:true}`. Không code nào đọc/gửi `datr` tường minh —
  browser tự gửi. Không có bằng chứng `datr` là bắt buộc cho native flow.
- Không có SDK fingerprinting/device-signal nào lộ diện trong chunk đã
  fetch (không chuỗi fingerprinting library; `deviceMemory` là Client Hint
  của trình duyệt, không phải device id). Không kết luận "không có
  fingerprinting" — chỉ "không thấy trong 44 chunk đã fetch".
- `document.cookie`: chỉ trong module cookie-manager
  (`writeToStorage`/`flushPendingCookies` + `POST /api/cookies/upgrade`):
  client tự ghi cookie non-HttpOnly và nhờ server upgrade cookie HttpOnly.
  Danh sách cookie nào đi qua đường này chưa trích — PARTIAL.
- `state`/`nonce`: `NonceMismatch`/`NonceMissing` là tên lỗi trong module
  cookie/error; `nonce` xuất hiện trong analytics login + OIDC. Không có
  contract `state` param nào cho native flow trong bundle đã fetch.

## 3. Code / 2FA branching + captcha

### 3.1 Sau khi verify mã (success path + các nhánh)

- `send-otp` → màn `otp` (hiển thị `masked_contact`, nút Resend code,
  "Enter the code we sent to {destination}"), hoặc màn `password`
  (khi `registration_state==="password_required"`), hoặc màn `accounts`
  (saved accounts). `password_login_available` (bool) điều khiển có cho
  chuyển sang password không.
- `confirm-otp` → outcome: `redirected` (navigate `url` — login xong),
  `twoFactor` (mở chọn phương thức 2FA + `setAnswer(!0)`),
  `reactivation` (dialog kích hoạt lại tài khoản), `completed`
  (`auth_meta_session: {frl_access_token, frl_account_id}` → logged in),
  hoặc error (xem §3.3).
- 2FA: chọn phương thức (`LOGIN_TWO_FACTOR_METHOD_SELECT_CLICK`) →
  nhập mã: TOTP = "Enter the 6-digit code … from the two-factor
  authenticator app"; SMS = "enter the code we sent"; `two-factor-send-code`
  gửi lại. Recovery codes: màn riêng, strip whitespace (`RECOVERY_CODES`
  → remove `\s`). Passkey (WebAuthn) được hỗ trợ: `navigator.credentials.get`
  với `{challenge, rpId, allowCredentials ≤100}`, event
  `PASSKEY_LOGIN_ASSERTION_SUCCESS`; `disarmPasskey` trên một số đường.
- Đăng ký mới (NTP flow): `birthday` (date_of_birth) → `create-password`
  (password qua `uQ`) → `register-completion` → upsell `ntp-upsell`
  (decline được) → `completion` với `masked_contact`. Age check phía
  server không thấy trong bundle (chỉ có màn birthday); prior guides
  nói age check qua Facebook/card/LinkedIn — không xác nhận từ bundle.

### 3.2 Mã sai / hết hạn / checkpoint / region

- Mã sai: "We couldn't verify that code. Try again."
  ("We couldn't send a code. Try again." cho send fail.)
- Hết hạn flow: error types `authFlowExpired`, `csrfFailed`,
  `session_invalid`, `invalidTwoFactorState`, `invalidSelection`,
  `invalidRecoveryState`, `invalidResetState` → restart `ay()`
  (`POST /restart`) rồi thử lại; restart fail → `restartFailed`.
- Checkpoint: sau login (hoặc khi session bị nghi ngờ), probe
  `/api/auth/check` trả 403 `{type:"checkpointRequired", checkpoint_url}`
  → client redirect tới `checkpoint_url` (trang checkpoint của Meta,
  browser-only), lưu `pending_checkpoint_handoff` (10 phút); khi quay lại:
  `/blocked?checkpoint_return=1`; các path `/checkpoint*` → qua
  `/api/oidc/start?checkpoint=1&return_to=...`. Terminate checkpoint:
  `POST /api/auth/checkpoint/terminate`. Checkpoint là nhánh
  **browser-only**: CLI không thể xử lý trang checkpoint của Meta bằng
  contract này — user phải tự qua checkpoint trong trình duyệt (hoặc
  screencast flow, ngoài phạm vi báo cáo này).
- Region: `region` từ locale trình duyệt gửi kèm `send-otp`; server có
  thể 403 `regionNotSupported`; client nhớ identifier đã bị chặn và hiện
  lỗi ngay không cần gọi lại. Region gating là server-enforced, không
  bypass được bằng header (chưa kiểm chứng — chỉ suy từ code client).

### 3.3 Error taxonomy (đầy đủ như trong bundle — tên `type`)

`authFlowExpired`, `csrfFailed`, `session_invalid`, `invalidRequest`,
`invalidTwoFactorState`, `invalidSelection`, `invalidRecoveryState`,
`invalidResetState`, `invalidSelection`, `contactPointIsTwoFactorMethod`,
`savedAccountUnavailable`, `pendingConfirmation`, `otpSendFailed`,
`twoFactorMethodUnsupported`, `twoFactorSessionExpired`, `tooManyAttempts`,
`twoFactorSendFailed`, `twoFactorLoginFailed`, `recoverySessionExpired`,
`weakPassword`, `passwordMatchesOld`, `regionNotSupported`,
`passwordRecoveryFailed`, `passwordResetFailed`, `completionHandleInvalid`,
`unsupportedVerification`. (Một số type chỉ thấy trong map hiển thị lỗi,
chưa thấy server trả về trong excerpt — ghi nhận là taxonomy, không
khẳng định từng type đều reachable.)

### 3.4 Captcha — chỉ những gì bundle cho thấy

- **Không có SDK captcha bên thứ ba nào** trong 44 chunk: grep
  `captcha|turnstile|recaptcha|hcaptcha|arkose|funcaptcha|grecaptcha|sitekey`
  — hit duy nhất là chữ "Cloudflare" trong một runtime-sniffer
  (Bun/Cloudflare-Workers/Deno/Node), không phải captcha; không có
  `<iframe>` nào trong chunk auth chính. Không có chuỗi UI captcha nào
  ("I'm not a robot", "verify you're human" — 0 hit).
- Điều đó KHÔNG chứng minh "không có captcha": checkpoint của Meta
  (trang checkpoint sau 403) có thể chứa captcha/challenge riêng, và
  checkbox first-party `oa` (§2.3) có thể là một dạng human-check.
  Phát biểu đúng: **bundle đã fetch không chứa captcha**; captcha (nếu có)
  nằm ở phía checkpoint/broker, ngoài tầm phân tích tĩnh này. Tuyệt đối
  không được bypass captcha/2FA — user luôn tự nhập mã và tự qua mọi
  challenge trong trình duyệt (hoặc screencast).

## 4. Verdict: PARTIAL — contract đủ để thiết kế, chưa đủ để build

### 4.1 Đã đủ (COMPLETE)

- Inventory endpoint + tên action + phần lớn body (OTP path, select-account,
  recovery-complete, aymh-cards, provider SSO start/complete).
- Crypto password `#PWD_BROWSER:5` khôi phục đầy đủ + xác nhận độc lập.
- CSRF rotation + waterfall-id mechanics + error taxonomy + outcome state
  machine (redirected/twoFactor/reactivation/completed).
- Checkpoint branching + region gating + passkey + recovery-code handling.
- Không có refresh endpoint (khớp prior report, nay có thêm bằng chứng bundle).

### 4.2 Còn thiếu (mỗi mảnh + cách lấy) — tất cả đều blocker cho replay

1. **`answerField()` / `submitAnswer()` payload shape** (checkbox first-party):
   nằm ở chunk lazy-load chứa component `oa`. Cách lấy: HAR do Boss capture
   khi tự login trong trình duyệt (chỉ tên field + kiểu giá trị, đã redact
   value), hoặc fetch chunk lazy-load khi route login được execute (cần
   browser — ngoài phạm vi read-only này).
2. **`oi.J()` header contents**: cùng cách lấy như (1) — HAR header NAMES
   của một POST `/send-otp` thật.
3. **Seed CSRF cho `/start` đầu tiên + full shape response `/bootstrap`**:
   HAR của lần load trang login (GET bootstrap → POST start), tên field only.
4. **`hatch_native_auth_*` mechanics**: bundle `auth.muse.ai` không fetch
   được khi không cookie; cách lấy: HAR Set-Cookie NAMES + attributes của
   Boss (không values), hoặc Boss fetch bundle auth app khi đã login.
5. **Provider SSO phía broker (`agent.meta.ai`)**: HAR của luồng
   provider-SSO (form fields + redirect chain, tên only).
6. **Lazy chunks chưa fetch**: route chunks load khi navigate tới màn login;
   danh sách đầy đủ cần thực thi app (browser/HAR), không có từ shell tĩnh.
7. **Server có validate TLS/UA/device ngoài cookie+header không**: phân tích
   tĩnh không trả lời được. Cách kiểm: probe không-credential (chỉ sau khi
   Boss duyệt): POST `/bootstrap` + `/start` body rỗng qua outbound, không
   identifier, xem có trả `csrf_token` hay challenge — chứng minh được
   bootstrap có replay được không mà không động tới tài khoản nào.

### 4.3 Fingerprint implication (một đoạn, theo prior findings — không redo engine comparison)

Luồng bundle tạo ra một **browser identity thật**: TLS stack + UA/Client Hints
của trình duyệt, cookie do browser quản (gồm `datr`), JS execution, WebAuthn,
locale-derived region, và checkbox challenge first-party. `tls_engine` của
CLI (cronet/utls/stdlib — đang được đánh giá riêng) chỉ xấp xỉ được
TLS + header, không tái tạo được JS execution, passkey, hay checkbox challenge.
Theo prior login research, mismatch fingerprint ở mức thường **đã chạy được
trong sản phẩm** (CLI luôn dùng identity Chrome cố định bất kể trình duyệt
login), nên parity fingerprint là desirable, không phải điều kiện tiên quyết
đã chứng minh — và giá trị thật của native flow (nếu replay được) là login
và traffic sau dùng CHUNG một identity của CLI theo cấu trúc. Blocker thực sự
là các mảnh contract ở §4.2 (đặc biệt challenge answer + `J()` headers),
không phải TLS fingerprinting.

## 5. Safe next step (Boss-driven, agent không chạm credential)

Chỉ thực hiện sau khi Boss duyệt verdict PARTIAL này. Agent KHÔNG tự chạy
bất kỳ bước nào dưới đây nếu chưa có lệnh riêng của Boss.

1. **HAR capture (Boss, máy của Boss):** mở DevTools → Network → Preserve log
   → tự login bình thường (gõ identifier + mã + qua checkpoint/2FA nếu có).
   Export HAR. Trước khi đưa agent: redact mọi VALUE (chỉ giữ: method, host,
   path, tên header, status, tên Set-Cookie + attributes, tên field JSON).
   Agent chỉ đọc HAR đã redact để điền §4.2 (1)–(5).
2. **Boss báo cáo boolean + tên bước:** bootstrap có trả `csrf_token` không?
   `/start` có cần seed gì không? checkbox có xuất hiện không (màn nào)?
   checkpoint có xuất hiện không? Mỗi câu trả lời chỉ là có/không + tên bước.
3. **Probe không-credential (chỉ khi Boss duyệt riêng):** CLI-shape
   `GET /bootstrap` + `POST /start {}` qua profile outbound, không identifier,
   không cookie thật — xem có nhận `csrf_token`/`password_encryption` hay bị
   challenge. Không động tới tài khoản, không request mã.
4. **Re-assess:** nếu HAR điền đủ (1)–(3) → verdict lên BUILDABLE và viết
   spec implementation; nếu HAR cho thấy challenge/device-signal bắt buộc
   không replay được → verdict NOT-BUILDABLE, dừng native, giữ screencast +
   `auth import` làm đáp án.

## 6. [UNVERIFIED] — kèm lệnh kiểm chứng

1. Seed CSRF cho `/start` + full shape `/bootstrap`: HAR bước 5.1 (chưa kiểm chứng).
2. `answerField()`/`submitAnswer()` shape + `oa` component: HAR bước 5.1, hoặc
   `grep -rn 'answerField' chunks/` sau khi có đủ chunk lazy-load (chưa kiểm chứng).
3. `oi.J()` header contents: HAR tên header của POST `/send-otp` (chưa kiểm chứng).
4. `hatch_native_auth_*` obtain/use: HAR Set-Cookie names/attributes của Boss
   (chưa kiểm chứng); lệnh đối chiếu tên: `grep -r 'hatch_native_auth' chunks/*.js`
   (đã chạy: 0 hit).
5. Phía broker `agent.meta.ai`: HAR luồng provider SSO (chưa kiểm chứng).
6. Captcha/checkpoint thực tế trên trang checkpoint: chỉ Boss tự login mới biết
   (chưa kiểm chứng; bundle đã fetch: không captcha).
7. Server validate TLS/UA/device ngoài cookie+header: probe không-credential
   bước 5.3, chỉ sau duyệt (chưa kiểm chứng).
8. Lifetime `hatch_sess` + expiry metadata: Boss `auth export` mới, đọc cột
   expires của jar Netscape (metadata only) — như prior report mục 7.3
   (chưa kiểm chứng).
9. Các action `two-factor-send-code` / `remove-cross-app-account` /
   recovery-`*` bodies: HAR tương ứng (chưa kiểm chứng; chỉ có tên).
10. Tính đầy đủ của 44 chunk: lazy chunks theo route chưa fetch; đối chiếu
    bằng HAR (danh sách URL `.js` thực tế load khi login) (chưa kiểm chứng).

## 7. Xác nhận tuân thủ

- **Zero POSTs sent:** mọi fetch trong task này đều GET (curl/browser.open/
  search). Không form nào được submit, không identifier/phone/email nào được
  gửi, không mã nào được request, không login attempt nào.
- **Zero credentials used:** không password, không mã, không token, không
  cookie thật nào được dùng hay đọc. Cookie file của muse01 không được mở.
- **Zero cookies sent:** curl không kèm `-b`/`-c`/cookie jar; `browser.open`
  không kèm cookie; search không kèm auth. Các response `Set-Cookie`:
  không có cái nào trong các fetch (fetch 3: 0 header Set-Cookie; fetch 4:
  0 header Set-Cookie — grep headers đã xác nhận).
- Không file worktree/repo nào bị sửa. Chỉ ghi scratch tại
  `~/workspace/tmp/native-bundle-analysis/` (HTML, headers, chunk, log).
