# WEB Proxy Panel — план реализации (v2)

Документ для Claude Code. Задача — собственная панель и Telegram-бот **только для Telegram WEB Proxy** на базе официального [`telegramdesktop/tproxy-server`](https://github.com/telegramdesktop/tproxy-server). Сервер выделенный: на нём нет ничего, кроме этого проекта.

[`POLESNIESOVETI12/web-panel-proxy`](https://github.com/POLESNIESOVETI12/web-panel-proxy) — только источник идей. Код оттуда не копировать: там VLESS/Hysteria2/AWG/OpenFlux и схема «один MTProxy на пользователя», которая не масштабируется.

> **Перед началом:** склонируй в `./reference/` (добавь в `.gitignore`):
> - `telegramdesktop/tproxy-server` на коммите `acc252ece3a25c29e9b83f608499a5567a33ab2a`;
> - `TelegramMessenger/MTProxy` на коммите `f36d8af769ffaeac36978d38c2c0f6d1104c2137`.
>
> Прочитай в tproxy-server: `README.md`, `PROTOCOL.md`, `BASE_PATH.md`, `HARDENING.md`, `PUBLIC_SITE.md`, весь `deploy/`, `internal/config/config.go`, `internal/session/*`.

---

## 0. Принятые решения

| Вопрос | Решение |
|---|---|
| Язык | **Python 3, только stdlib**: `http.server`, `sqlite3`, `hashlib`, `hmac`, `urllib`, `subprocess`, `json`. Никакого pip. Внешние утилиты из apt: `qrencode`, `nftables`, `iproute2` (`ss`). |
| Хранилище | **SQLite** (`sqlite3`, WAL). Панель, бот и воркер пишут одновременно; JSON-файл для 300+ пользователей и поминутной статистики не годится. |
| Системный пользователь | **Один Linux-пользователь `webproxy`**. От него работают все сервисы: Caddy, relay, все MTProxy, панель, бот, воркер. Root нужен только маленькому помощнику `wppctl` для nft, `ss -K` и systemctl. Он вызывается через `sudo` с белым списком. |
| Доступ к панели | Секретный путь на основном домене: `https://<домен>/<panel_path>/`. |
| Масштаб | 300 пользователей из коробки, рост до ~1000+ без переделок. |
| Выдача доступа | 1) заявка через бота с ручным или автоматическим одобрением (переключатель в панели); 2) ручное создание в панели с указанием Telegram ID. |
| Протоколы | Только WEB Proxy. MTProxy наружу не открывается. |
| Сервер | Размер пока неизвестен → инсталлятор **сам считает лимиты** по CPU/RAM (раздел 9). |

---

## 1. Факты из исходников, на которых стоит архитектура

### tproxy-server (relay)
1. Схема: `:443 Caddy → 127.0.0.1:8080 relay → 127.0.0.1:<port> MTProxy`. Админ-эндпоинты relay: `127.0.0.1:8081` (`/healthz`, `/readyz`, `/metrics`).
2. Пользователь relay = **профиль** в `profiles.json`: `name`, `secret` (32 hex, допускается префикс `dd`), `backend` (loopback `ip:port`), `carrier_mode`, необязательные `limits` (только понижают глобальные, например `max_sessions`).
3. **Профили читаются только при старте.** Любое изменение `profiles.json` означает рестарт relay и обрыв сессий у всех.
4. Количество профилей ограничено `limits.max_profiles` в `config.json` (по умолчанию 32, жёсткого верхнего предела в коде нет, только `> 0`).
5. По умолчанию `max_sessions_global = 128`: это **потолок для 300 пользователей**, его надо поднимать вместе с памятью (раздел 9). Relay отказывается стартовать, если резерв на сессию × `max_sessions_global` не помещается в `max_pending_global` / `max_pending_items_global`. Найди этот расчёт в `internal/session` и повтори его в инсталляторе.
6. Relay не знает трафика по профилям: `/metrics` отдаёт только глобальные счётчики.
7. Проверка без запуска: `tproxy-server -config <cfg> -profiles-file <file> -check`.
8. **Ссылка для клиента** зависит от `base_path`:
   - без префикса: `https://t.me/webproxy?server=<домен>&secret=<32 hex>`;
   - с префиксом: `https://t.me/webproxy?server=<urlencode("домен/prefix")>&secret=<marked>`, где `marked` = base64url без `=` от `0x70 ‖ байты_секрета`;
   - тест-вектор: `8561944064fc730cbfa4473562d8ec59` → `cIVhlEBk_HMMv6RHNWLY7Fk`;
   - тест-векторы capability — таблица в `BASE_PATH.md` §1.
9. Token key: 32 случайных байта в `token_key_file`. Его нельзя терять при обновлениях (см. `deploy/ensure-token-key.sh`, `HARDENING.md`).

### MTProxy (официальный)
10. **Максимум 16 секретов на процесс**: `static unsigned char ext_secret[16][16]` и `assert(ext_secret_cnt < 16)` в `net/net-tcp-rpc-ext-server.c`. Проверь в коде, 15 или 16 реально помещается (строгое `<` перед инкрементом → 16), и возьми безопасное значение.
11. **До 128 клиентских портов на процесс**: `-H 20000,20001,...`, `MAX_HTTP_LISTEN_PORTS 128`.
12. Если процесс запущен не от root, `-u` ничего не делает (`change_user` в `common/server-functions.c`). Поэтому MTProxy можно запускать сразу от `webproxy`.
13. Нужны `proxy-secret` и `proxy-multi.conf` с `core.telegram.org` с ежедневным обновлением. На NAT-хостах (облака) нужен `--nat-info <local>:<public>`, иначе MTProxy молча не работает (см. upstream `mtproxy.service` и `install.sh`).

---

## 2. Архитектура: шарды и слоты

**Слот** — это место для одного пользователя: свой секрет, свой loopback-порт, свой профиль в relay.
**Шард** — один процесс MTProxy на 16 слотов: 16 `-S` и 16 портов в `-H`.

```
Caddy :443 ──┬── /<panel_path>/*  → 127.0.0.1:8090  wpp-panel
             └── всё остальное    → 127.0.0.1:8080  tproxy-server
                                          │ профиль s000-00 → 127.0.0.1:20000
                                          │ профиль s000-01 → 127.0.0.1:20001
                                          │ …
                                          ▼
     wpp-mtproxy@0  (-H 20000..20015, 16×-S)      wpp-mtproxy@1 (-H 20016..20031) …
```

- Порт слота: `20000 + shard*16 + i`. Stats-порт шарда: `19000 + shard`. Имя профиля: `s{shard:03d}-{i:02d}` (без имён людей и секретов).
- 300 пользователей → 19–20 шардов. 1000 → 63. Процессов немного, память предсказуема.
- Внутри шарда MTProxy примет любой из 16 секретов на любом из 16 портов. Это не проблема: relay по capability направляет пользователя **только на его порт**, а по порту считаем трафик и управляем доступом.

### Управление доступом без рестартов (nftables)
Таблица `inet wpp`, **именованные множества и счётчики**, без перебора правил:
```
set blocked { type inet_service; }                   # закрытые порты слотов
chain out { type filter hook output priority -10;
  oifname "lo" tcp dport @blocked reject with tcp reset
  oifname "lo" tcp dport 20000-29999 counter name tcp dport map @cnt_up
}
chain in  { type filter hook input priority -10;
  iifname "lo" tcp sport 20000-29999 counter name tcp sport map @cnt_down
  iifname != "lo" tcp dport { 8080, 8081, 8090, 19000-29999 } drop
}
```
Точный синтаксис `counter name … map` проверь на nft 1.0.2 (Ubuntu 22.04) и 1.0.6 (Debian 12). Если не поддерживается — запасной вариант: по правилу `counter` с comment на каждый порт в отдельной цепочке с `vmap` переходом по порту.

| Действие | Что происходит | Рестарт |
|---|---|---|
| Новый слот (свободный) | порт в `@blocked` | — |
| Выдать доступ | взять **чистый** свободный слот, удалить порт из `@blocked` | нет |
| Выключить | добавить в `@blocked` + `ss -K` на порт (обрыв текущих потоков) | нет |
| Включить | удалить из `@blocked` | нет |
| Перевыпустить ссылку | пользователь переезжает на новый чистый слот, старый: выключить → `dirty` | нет |
| Удалить | выключить, слот → `dirty` | нет |
| Очистка dirty | новые секреты dirty-слотов → env шарда → рестарт шарда(ов) + relay | **да, пачкой** |
| Расширение пула | новые шарды + профили | **да** |

Статусы слота: `free` (чистый, никогда не выдавался или перевыпущен), `assigned`, `dirty` (выдавался, секрет мог утечь, повторно не выдаётся).

**Окно обслуживания** (по умолчанию 04:30, настраивается): если есть dirty-слоты или чистых свободных меньше порога (`max(16, 10% пула)`), выполняется очистка/расширение. Перед этим уведомление админу, после — отчёт.
**Аварийно:** если чистых слотов 0, а нужно выдать доступ, то в ручном режиме панель предлагает «Расширить сейчас (все переподключатся)», а в автоматическом режиме заявка ждёт окна, пользователю бот пишет «доступ будет выдан в течение суток». Поведение настраивается.

Каждое изменение `profiles.json` и `config.json`: запись во временный файл → `-check` → атомарная замена → рестарт → ожидание `/healthz` и `/readyz` → при сбое откат на прошлую версию.

---

## 3. Один системный пользователь

Инсталлятор создаёт `webproxy` (`useradd --system --home /var/lib/webproxy --shell /usr/sbin/nologin`).

От `webproxy` работают все systemd-сервисы:

| Юнит | Что |
|---|---|
| `wpp-caddy.service` | Caddy, `AmbientCapabilities=CAP_NET_BIND_SERVICE` для 80/443 |
| `wpp-relay.service` | tproxy-server |
| `wpp-mtproxy@N.service` | шард N |
| `wpp-panel.service` | веб-панель |
| `wpp-bot.service` | Telegram-бот |
| `wpp-worker.service` + `.timer` | каждые 60 с: трафик, сроки, лимиты, уведомления, окно обслуживания |
| `wpp-refresh.service` + `.timer` | раз в сутки обновление `proxy-multi.conf`, рестарт шардов при изменении |
| `wpp-firewall.service` | oneshot, root, создаёт `table inet wpp` и восстанавливает `@blocked` из БД; `PartOf=nftables.service` |

Корень только у `wpp-firewall` (oneshot) и у `/usr/local/sbin/wppctl`. Sudoers `/etc/sudoers.d/webproxy`:
```
webproxy ALL=(root) NOPASSWD: /usr/local/sbin/wppctl
```
`wppctl` — единственная точка привилегий. Подкоманды из белого списка, аргументы валидируются заново:
- `block <port>...`, `unblock <port>...` (с `ss -K` для block);
- `restart relay | shard <N> | caddy`, `start|stop shard <N>`, `daemon-reload`, `enable shard <N>`;
- `install-shard-unit <N>`, `status`.

Файлы `profiles.json`, `config.json`, env шардов, БД принадлежат `webproxy` и пишутся напрямую, без root.

Все юниты с ужесточением как в upstream: `NoNewPrivileges`, `ProtectSystem=strict` + `ReadWritePaths`, `PrivateTmp`, `ProtectHome`, `ProtectProc=invisible`, `RestrictAddressFamilies`. У relay и MTProxy `IPAddressAllow=localhost` плюс для MTProxy разрешить исходящие к серверам Telegram. У панели `IPAddressAllow=localhost`. Боту нужен выход в интернет.

> Компромисс: при одном пользователе взлом панели даёт доступ к секретам и relay. Это принято ради простоты. Панель поэтому не должна исполнять ничего из пользовательского ввода, а все вызовы `subprocess` делаются только со списком аргументов.

**Каталоги:**
```
/opt/webproxy/            код (root:root, 0755), бинарники relay, MTProxy, caddy
/etc/webproxy/            config.json панели, relay config.json, profiles.json, token.key, shards/N.env, Caddyfile (webproxy, 0700)
/var/lib/webproxy/        wpp.db, caddy data (сертификаты), site/ (заглушка), backups/
```

---

## 4. База данных (SQLite, `/var/lib/webproxy/wpp.db`)

`PRAGMA journal_mode=WAL; foreign_keys=ON; busy_timeout=5000`. Миграции по `PRAGMA user_version`.

```sql
shards(id INTEGER PK, stats_port, created_at)
slots(id INTEGER PK, shard_id, idx, port UNIQUE, secret, status CHECK(status IN('free','assigned','dirty')), user_id NULL)
users(
  id INTEGER PK, name, tg_id INTEGER UNIQUE NULL, tg_username, tg_bot_started INTEGER DEFAULT 0, tg_blocked_bot INTEGER DEFAULT 0,
  slot_id NULL, enabled, disabled_reason NULL,        -- manual|expired|traffic_limit
  created_at, created_by,                             -- panel|bot_manual|bot_auto
  expires_at NULL, traffic_limit_bytes NULL, traffic_reset TEXT,   -- never|monthly
  period_start, period_up, period_down, total_up, total_down, last_seen_traffic_at,
  note, notified_flags
)
requests(id PK, tg_id, tg_username, tg_name, comment, created_at, status, -- pending|approved|rejected|expired
         decided_at, decided_by, admin_msg_ids JSON)
bans(tg_id PK, reason, created_at)
traffic_hourly(user_id, hour, up, down, PRIMARY KEY(user_id,hour))     -- хранить 90 дней
counters_last(port PK, up, down)                                      -- последние значения счётчиков nft
settings(key PK, value)                                               -- все настройки панели
events(id PK, ts, kind, user_id NULL, details)                        -- журнал без секретов, хранить 30 дней
maintenance(id PK, ts, kind, result)
```
Индексы: `users(enabled)`, `users(expires_at)`, `users(name)`, `requests(status)`, `slots(status)`.

---

## 5. Выдача доступа

### 5.1 Через бота (заявка)
1. Человек пишет боту `/start`. Бот отмечает `tg_bot_started` (если такой `tg_id` уже есть в `users`, сразу присылает ссылку, см. 5.2).
2. Кнопка **«Запросить доступ»** → бот просит необязательный комментарий («Кто вы / от кого», можно пропустить).
3. Проверки: не в бане; нет активной заявки; нет действующего доступа; прошёл cooldown после отказа (настройка, по умолчанию 24 ч); глобальный лимит новых заявок (например, 30/час). При нарушении — вежливый ответ.
4. Режим одобрения (настройка `approval_mode`):
   - **`manual`** — всем админам приходит сообщение: имя, @username, ID, комментарий, дата. Инлайн-кнопки: `✅ 30 дней` `✅ 90 дней` `✅ Бессрочно` `❌ Отклонить` `🚫 Бан`. Заявка также появляется во вкладке «Заявки» панели. Кто нажал первым, тот и решил; у остальных админов сообщение редактируется («Одобрено админом X»).
   - **`auto`** — пользователь создаётся сразу с дефолтными сроком и лимитом из настроек, админам уходит уведомление с кнопками `Отключить` / `Удалить`.
5. При одобрении создаётся пользователь (`name` = имя из Telegram, можно поправить в панели), выдаётся слот, бот отправляет пользователю ссылку, QR (PNG) и короткую инструкцию.
6. Пользователь может отменить свою заявку.
7. Заявки старше N дней (настройка, 7) → `expired`.

### 5.2 Вручную в панели
Форма: имя (обязательно), Telegram ID (необязательно, но рекомендуется), срок, лимит трафика, тип сброса, заметка.
- Если указан `tg_id` и человек уже нажимал `/start` у бота — ссылка отправляется сразу.
- Если не нажимал — статус «Ожидает /start». Панель показывает ссылку на бота `https://t.me/<bot>` для пересылки. Как только человек нажмёт `/start`, бот сам отправит доступ. Бот не может написать первым: это ограничение Telegram.
- Ссылка и QR всегда доступны в панели для ручной передачи.
- `tg_id` уникален: один Telegram-аккаунт — один доступ. Одна ссылка работает на всех устройствах этого человека.
- Подсказка в форме: как узнать ID (человек пишет боту `/id`, бот отвечает его числовым ID; это работает всегда, без заявки).

### 5.3 Команды пользователя в боте
`/start`, `/id`, `/link` (прислать ссылку и QR снова, если доступ активен), `/status` (срок, трафик/лимит, состояние), `/help`. Главное меню — reply-клавиатура с этими пунктами.

Пользователю бот сам сообщает: доступ выдан, ссылка перевыпущена, осталось 3 дня, использовано 90% лимита, доступ отключён (с причиной), доступ восстановлен.

---

## 6. Telegram-бот (реализация)

- Long polling `getUpdates` (`timeout=50`, `allowed_updates=["message","callback_query"]`), `urllib.request`, отдельный процесс. Если `api.telegram.org` недоступен, повторять с экспоненциальной задержкой. Панель и прокси от бота не зависят.
- Исходящие через **очередь с лимитом**: не больше ~25 сообщений/с глобально и 1/с на чат. На `429` ждать `retry_after`. На `403` (бот заблокирован) ставить `tg_blocked_bot=1`, в панели показывать значок.
- QR: `qrencode -t PNG -o - -s 8 -- <link>` → `sendPhoto` multipart (собрать multipart вручную, stdlib).
- Админы — список `admin_tg_ids` в настройках. Только они получают заявки и могут нажимать callback-кнопки; callback от чужих ID игнорируется. В `callback_data` класть только `req:<id>:<action>`, решение перепроверять по БД.
- **Команды админа:** `/panel` (ссылка на панель), `/stats` (пользователи всего/активных, заявки, трафик за сутки, здоровье), `/find <имя|@username|id>`, `/pending` (заявки), `/mode manual|auto`.
- **Уведомления админу** (каждое отключаемо в настройках): новая заявка; автоодобрение; пользователь истёк / выбрал лимит; relay или шард упал и восстановился; результат окна обслуживания; заканчиваются свободные слоты; успешный вход в панель с IP.
- **Рассылка** из панели всем активным, всем с привязанным Telegram или выбранным. Текст (без HTML), предпросмотр, прогресс, итог «доставлено / заблокировали бота».
- Все тексты бота на русском, лежат в одном модуле `texts.py`.

---

## 7. Трафик, сроки, лимиты (wpp-worker, каждые 60 с)

1. `nft -j list counters table inet wpp` (или через `wppctl`, если чтение требует root) → байты по порту.
2. `delta = cur - last` (если `cur < last`, значит таблица пересоздавалась → `delta = cur`). Дельта начисляется пользователю, который **сейчас** владеет слотом. При назначении слота `counters_last` для порта сбрасывается на текущее значение.
3. Одна транзакция: обновить `period_*`, `total_*`, `traffic_hourly`.
4. Проверки:
   - `expires_at <= now` → выключить, `expired`;
   - период ≥ лимита → выключить, `traffic_limit`;
   - `monthly`: в начале месяца обнулить период и включить обратно тех, кто был выключен по `traffic_limit`;
   - предупреждения за 3 дня и на 90% (однократно, флаги в `notified_flags`).
5. При продлении срока или увеличении лимита в панели: если причина отключения устранена, включить (галочка «сразу включить», по умолчанию да).
6. Health: `/healthz`, `/readyz`, статус всех юнитов; уведомление при смене состояния, не чаще раза в 30 мин на один компонент.
7. Окно обслуживания (раздел 2).
8. Раз в сутки чистка старых `traffic_hourly`, `events`, `requests`; бэкап БД через `sqlite3` backup API в `/var/lib/webproxy/backups/` (хранить 7).

Трафик — это байты MTProxy-потока на loopback. В UI подписывать «≈ трафик Telegram».

---

## 8. Веб-панель

### Сервер и безопасность
- `ThreadingHTTPServer` на `127.0.0.1:8090`. Все маршруты под `/<panel_path>` (`p-` + 32 hex). Другие пути → 404.
- IP клиента — последний элемент `X-Forwarded-For` от Caddy.
- Заголовки: `Cache-Control: no-store`, CSP `default-src 'self'; img-src 'self' data:; script-src 'self'; style-src 'self'; frame-ancestors 'none'`, `X-Content-Type-Options: nosniff`, `Referrer-Policy: no-referrer`, `X-Robots-Tag: noindex`. Никаких inline-скриптов и `on*=`, без CDN. Весь вывод через `html.escape`.
- Один админ-логин. Пароль минимум 10 символов, `hashlib.scrypt(n=2**15,r=8,p=1)`.
- Сессия: подписанная HMAC cookie `HttpOnly; Secure; SameSite=Strict; Path=/<panel_path>`, 12 ч скользящая; смена пароля инвалидирует все сессии.
- CSRF-токен во всех POST. Блокировка 15 мин после 5 неудачных входов с IP + глобальный лимит.

### Страницы (интерфейс на русском, адаптивный под телефон)
1. **Дашборд:** пользователи (всего / активные / выключенные / истекают за 7 дней), заявки в ожидании, слоты (свободные / занятые / dirty) и шарды, сессии и потоки relay из `/metrics`, трафик за сутки/30 дней (SVG-график), CPU/RAM/диск, статус юнитов, баннер «Есть отложенные изменения — Применить сейчас (все переподключатся)».
2. **Пользователи:** серверная **пагинация** (50 на страницу), поиск по имени / @username / ID, фильтры (статус, истекающие, превысившие 80% лимита, без Telegram), сортировка (имя, трафик, срок, создан). Массовые действия с чекбоксами: выключить, включить, продлить на N дней, удалить, отправить сообщение.
3. **Пользователь:** параметры, ссылка + QR, график трафика по часам/дням за 30 дней, действия (вкл/выкл, продлить, лимит, перевыпустить ссылку, отправить ссылку в Telegram, удалить), журнал событий пользователя.
4. **Создать пользователя:** форма из 5.2.
5. **Заявки:** список pending с кнопками как в боте; история решений.
6. **Рассылка** (раздел 6).
7. **Настройки:**
   - Бот: токен, `admin_tg_ids`, кнопка «Проверить» (`getMe` + тестовое сообщение), username бота подставляется автоматически.
   - Заявки: режим `manual/auto`, дефолтный срок и лимит для автоодобрения и кнопок, cooldown, приём заявок вкл/выкл, срок жизни заявки, баны (список с разбаном).
   - Уведомления: чекбоксы.
   - Пул: размер (добавить шарды), время окна обслуживания, `max_sessions` на пользователя (защита от раздачи ссылки; применяется при следующем рестарте relay).
   - Безопасность: смена пароля, сменить путь панели (новый путь отправляется админам в бот).
   - Инфо: домен, base_path, версии relay/MTProxy/панели.
8. **Журнал:** события с фильтром по типу.

### Ссылка и QR
Одна функция `links.build(domain, base_path, secret_hex)` с unit-тестами на векторы из раздела 1. QR в панели: `qrencode -t SVG`.

---

## 9. Размер сервера и лимиты (автоподбор)

Размер сервера неизвестен, поэтому инсталлятор определяет `nproc` и `MemTotal` и рассчитывает параметры. Итог показывается и сохраняется в `/etc/webproxy/sizing.json`; пересчёт — командой `wpp-sizing`.

Исходные допущения (Claude Code должен **замерить** реальные значения на тестовом VPS и поправить формулы):
- `sessions_per_user` ≈ 2 (телефон + компьютер);
- потоков на сессию: взять соотношение upstream по умолчанию (4096/128 = 32) как верхнюю оценку;
- RSS одного шарда MTProxy — **замерить** в простое и под нагрузкой;
- relay: `max_pending_global` не больше ~25% RAM.

Расчёт:
```
users_target      = ввод при установке (по умолчанию 300)
pool_slots        = ceil(users_target * 1.1 / 16) * 16
max_profiles      = pool_slots + 16 (запас)
max_sessions_global = users_target * sessions_per_user   (проверить, что проходит -check по резерву)
max_streams_global  = min(max_sessions_global * 32, 65536)
max_pending_global  = min(512 MiB, RAM * 0.25) → если -check не проходит, снизить потоки/сессии и предупредить
MTProxy -C на шард  = с запасом от потоков 16 пользователей
LimitNOFILE        = 1048576 у relay и шардов
```
Если памяти мало для `users_target`, инсталлятор предупреждает и предлагает меньшее число.

Ориентир для README (уточнить после замеров): до ~100 пользователей — 1 vCPU / 1 ГБ; 300 — 2 vCPU / 2 ГБ; 1000 — 4 vCPU / 4–8 ГБ. Основную нагрузку дают TLS в Caddy и relay, а не MTProxy: добавлять CPU, если relay или Caddy упираются в CPU.

Также настроить `sysctl`: `net.core.somaxconn`, `net.ipv4.ip_local_port_range` (у relay много исходящих соединений на loopback), `fs.file-max`, BBR + `fq`.

---

## 10. Установка

Одна команда: `bash <(curl -fsSL .../install.sh)`. Скрипт **свой**, идемпотентный. Шаги upstream `deploy/install.sh` переносятся, но под одного пользователя `webproxy` и наши пути. Upstream-инсталлятор не вызывается: он создаёт отдельных пользователей `tproxy`, `mtproxy`, `caddy` и свой Caddyfile.

1. Проверки: root, Ubuntu 22.04+/Debian 12+, x86_64, systemd, домен резолвится во внешний IP сервера, 80/443 свободны.
2. Вопросы (с дефолтами): домен; email для ACME; логин админа; пароль (Enter → сгенерировать); ожидаемое число пользователей (300); base_path (Enter → случайный); токен бота и Telegram ID админа (можно пропустить и задать позже в панели). Если токен введён, попросить написать боту `/start`, прочитать `getUpdates` и показать найденный ID для подтверждения.
3. `apt`: `nftables qrencode curl git build-essential libssl-dev zlib1g-dev sqlite3 iproute2 python3`.
4. Создать пользователя `webproxy` и каталоги.
5. Caddy: проверенный по SHA256 официальный бинарник (как в upstream), свой юнит от `webproxy`.
6. Go (проверенный архив, если нет ≥ 1.20) → `go test ./...` → сборка relay закреплённого коммита → `/opt/webproxy/bin/tproxy-server`.
7. MTProxy закреплённого коммита (проверка архива как в upstream `install-mtproxy.sh`) → `/opt/webproxy/bin/mtproto-proxy`; скачать `proxy-secret`, `proxy-multi.conf`; определить NAT (сравнить локальный IP интерфейса с внешним) → `--nat-info`.
8. `token.key` (32 байта, не перезаписывать существующий).
9. Сайт-заглушка в `/var/lib/webproxy/site`: генерировать **уникальную** страницу (случайные тексты/цвета/структура из нескольких вариантов), чтобы установки не имели одинакового HTML. Или путь к своей папке.
10. Расчёт лимитов (раздел 9) → `config.json` relay.
11. Инициализация БД, шардов и слотов → `profiles.json`, `shards/N.env` → `-check`.
12. Caddyfile (сервер выделенный, файл целиком наш): глобальные опции как в upstream (`admin off`, `protocols h1 h2`, таймауты `read_body` 60s), блок домена: `header -Via`, HSTS, `handle /<panel_path>/*` → 8090, `handle` → 8080 с `response_header_timeout 40s`, `handle_errors` как в upstream. Без access-логов.
13. Firewall хоста (сервер выделенный): `inet filter input policy drop`, разрешить `lo`, established, ICMP, **SSH-порт** (определить из `sshd -T`, спросить подтверждение), 80, 443. Перед применением показать правила; применять с таймером автоотката 60 с, если админ не подтвердил, что SSH жив. Учесть UFW, если он включён.
14. `sysctl`, юниты, `systemctl enable --now`, дождаться сертификата и `/readyz`.
15. Создать первого пользователя «Админ» (с Telegram ID админа, если есть).
16. Итог: URL панели, логин, пароль, ссылка первого пользователя; если бот настроен — ссылка на панель уходит админу в Telegram.
17. Лог установки → `/var/log/webproxy-install.log` без секретов.

**`update.sh`:** бэкап `/etc/webproxy` + БД → новый код → миграции БД → рестарт `wpp-panel`, `wpp-bot`, `wpp-worker`. Обновление relay/MTProxy до нового закреплённого коммита — отдельный флаг `--core` (сборка, `-check`, атомарная замена, откат при провале health, по образцу upstream `update-relay.sh`).
**`uninstall.sh`:** подтверждение вводом домена, удаляет всё наше: юниты, `table inet wpp`, правила firewall, `/opt|/etc|/var/lib/webproxy`, sudoers, пользователя.
**CLI `wpp`** (для SSH): `wpp status`, `wpp panel-url`, `wpp reset-password`, `wpp backup`, `wpp logs`.

---

## 11. Структура репозитория

```
install.sh  update.sh  uninstall.sh  README.md
webproxy/
  config.py        settings, пути
  db.py            подключение, миграции, транзакции
  links.py         ссылки, marked secret, capability (самопроверка)
  pool.py          шарды/слоты: assign, release, rotate, grow, генерация profiles.json и env
  system.py        обёртки над sudo wppctl, relay -check, health, qrencode (только списки аргументов)
  users.py         бизнес-логика: create/enable/disable/extend/rotate/delete — общая для панели и бота
  requests.py      заявки, баны, cooldown, auto/manual
  traffic.py       nft → дельты → БД
  worker.py        минутный цикл + окно обслуживания
  sizing.py        раздел 9
  auth.py          scrypt, сессии, CSRF, rate limit
  panel/server.py  роутинг, views.py, static/{app.css,app.js}
  bot/client.py    Bot API, очередь отправки
  bot/handlers.py  команды, callback-и
  bot/texts.py
  ctl.py           wppctl (root)
systemd/  *.service *.timer
tests/    unittest: links, pool, traffic-дельты, requests, users (с фиктивным system.py), sizing
```

Бизнес-логика (`users.py`, `requests.py`, `pool.py`) не знает про HTTP и Telegram. Панель и бот вызывают одни и те же функции.

---

## 12. Этапы

**M1 — ядро.** `db`, `links`, `pool`, `system`, `ctl`, `users`, шаблон шарда, nft-таблица. Тесты. **Критерий:** на тестовом VPS 20 шардов / 320 слотов; выдача, выключение и включение не рвут соединения других; выключенный пользователь отваливается за секунды; ссылки с base_path и без работают в Telegram с поддержкой WEB proxy.

**M2 — трафик и воркер.** Счётчики, сроки, лимиты, health, окно обслуживания (время передавать параметром, тесты со сдвигом). **Критерий:** трафик начисляется правильному пользователю, переживает `systemctl restart nftables` и перевыпуск слота.

**M3 — панель.** Все страницы из раздела 8, пагинация и поиск на 1000 фейковых пользователях. **Критерий:** страница пользователей < 200 мс.

**M4 — бот.** Заявки (manual/auto), ручное создание по ID, команды пользователя и админа, уведомления, рассылка с лимитами.

**M5 — установка.** install/update/uninstall на чистых Ubuntu 22.04, 24.04, Debian 12; повторная установка не теряет данные; автоматический откат firewall.

**M6 — нагрузка и замеры.** Скрипт нагрузочного теста (много сессий через relay к шардам), замер RAM/CPU, уточнение формул раздела 9 и таблицы в README.

---

## 13. Чего не делать

- Не менять код tproxy-server и MTProxy — только конфиги.
- Не запускать панель, бота и сервисы от root (кроме `wpp-firewall` oneshot и `wppctl`).
- Не логировать ссылки, секреты, URL моста, заголовки Authorization; никаких access-логов в Caddy.
- `subprocess` только со списком аргументов, никогда `shell=True`; JSON и конфиги не править через `sed`.
- Не перевыдавать `dirty`-слоты без смены секрета.
- Не рестартовать relay вне окна обслуживания без явного подтверждения админа.
- Никаких CDN и внешних ресурсов в панели и заглушке.

## 14. Проверить в коде до начала M1

1. MTProxy: точно ли 16 секретов (граница `assert`), корректен ли `-H` с 16 портами, как ведёт себя `ss -K` для соединений relay→MTProxy на loopback (ядро с `CONFIG_INET_DIAG_DESTROY`, на Ubuntu/Debian включено — проверить).
2. Relay: отказ `connect` к backend одного профиля (reject) даёт только `CLOSE` потока и не делает `/readyz` красным. Если `/readyz` проверяет все backend-ы, в health учитывать только живость процессов шардов.
3. Relay: формула резерва на сессию против `max_pending_*` для корректного `-check` при больших `max_sessions_global`.
4. Relay: поддерживает ли per-profile `limits.max_sessions` нужную семантику «макс. устройств».
5. nft: синтаксис именованных счётчиков через map на целевых версиях.
6. Что делает relay с сессией, у которой все потоки получают `CLOSE` (не зацикливается ли клиент в частых переподключениях и не бьёт ли в `new_sessions_per_minute`). Если да — для выключенных пользователей лучше не reject, а оставить как есть и отвечать быстро, но проверить поведение на реальном клиенте.

## 15. На будущее

- `carrier_mode` на пользователя (подпулы шардов с разными режимами).
- Тарифы с оплатой через бота.
- Несколько серверов под одной панелью.
