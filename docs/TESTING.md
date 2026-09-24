# Проверка на сервере

Локально (macOS) выполняются только `python3 -m unittest` и `bash -n`. Всё остальное проверяется
на тестовом VPS (Ubuntu 22.04/24.04, Debian 12, x86_64). Скрипты `tools/verify/*.sh` самодостаточны:
печатают `PASS`/`FAIL`/`INFO` и итоговую строку `ИТОГ:`, всё временное удаляют за собой.

## Подготовка

```bash
git clone https://github.com/barakov-dot/tg-proxy-panel-v2.git
```

```bash
cd tg-proxy-panel-v2 && git checkout <тег>
```

## Этап 0 — проверка допущений (docs/FINDINGS.md)

Запускать на чистом VPS, до установки панели. Скриптам нужны свободные порты 29870–29999.

| Скрипт | Что проверяет | Пункты FINDINGS |
|---|---|---|
| `sudo bash tools/verify/nft-ss.sh` | синтаксис `table inet wpp` на установленной версии nft, счётчики по портам, reject, `ss -K` только для одного порта, добавление счётчиков в живую таблицу | 1, 5 |
| `sudo bash tools/verify/mtproxy-shard.sh --install-deps` | сборка MTProxy закреплённого коммита, 16 секретов/16 портов, 17 — отказ, `-u` без root, `/stats`, RSS для `-M 1` и `-M 0`, связь с middle-end | 1, 7, 8 |
| `sudo bash tools/verify/relay-check.sh` | граница `-check` по резерву сессии, 1024 профиля, `/readyz` при отказе backend, `max_sessions` профиля, `CLOSE` при отказе backend, изоляция ведра потоков; печатает SHA-256 архива relay | 2, 3, 4, 6 |

`--install-deps` ставит через apt пакеты сборки из плана (`build-essential libssl-dev zlib1g-dev curl iproute2`).
Их не удаляем: они всё равно нужны установщику. `relay-check.sh` скачивает Go во временный каталог,
если в системе нет Go ≥ 1.20.

Что прислать в ответ: полный вывод трёх скриптов, `nft --version`, `uname -r`, `cat /etc/os-release | head -3`.
Результаты RSS и SHA-256 архива relay вносятся в FINDINGS.md.

### Ручная проверка с реальным клиентом (после M1)

`tools/verify/client-reconnect-watch.sh [секунд] [admin] [порог]` — наблюдение за `/metrics` relay,
пока открыт клиент Telegram с выключенным доступом. Остальные клиенты на время замера отключить.
PASS, если клиент создаёт не больше порога потоков в минуту (по умолчанию 120).
Дополнительно смотрим, растёт ли `sessions_created` (клиент пересоздаёт WebView-сессию).

## M1 — ядро (тег `v0.1.0`)

Нужны: чистый VPS (Ubuntu 22.04/24.04 или Debian 12, x86_64), домен с A-записью на сервер, открытые 80/443.
Стенд ставится скриптом `tools/dev/bringup.sh` — это **не** установщик (он будет в M5): без вопросов,
без firewall хоста, без панели и бота. Повторный запуск безопасен.

```bash
git clone --branch v0.1.0 https://github.com/barakov-dot/tg-proxy-panel-v2.git /opt/webproxy/src
```

```bash
bash /opt/webproxy/src/tools/dev/bringup.sh --domain proxy.example.com --email you@example.com --users 240
```

`--users 240` даёт ⌈240 × 1,2 × 1,1 / 16⌉ = 20 шардов / 320 слотов (критерий M1). `--base-path none` — без префикса,
без параметра — случайный префикс. Сборка relay и MTProxy занимает несколько минут.

### 1. Автоматическая проверка (без клиента Telegram)

```bash
bash /opt/webproxy/src/tools/verify/m1-core.sh
```

Ожидается `ИТОГ: PASS`: сессии и потоки через relay; выключение A закрывает его поток за секунды и не
трогает B; новые потоки выключенного A отклоняются; после включения работают; вторая одновременная
сессия по одной ссылке — 503; после перевыпуска старый слот закрыт, новая ссылка работает.

Состояние пула и юнитов:

```bash
sudo -u webproxy python3 -m webproxy.cli --config /etc/webproxy/config.json status
```

(запускать из `/opt/webproxy/src`). Ожидается: 20 шардов, все `wpp-mtproxy@N` active, relay `/healthz` ok.

```bash
nft list table inet wpp | head -n 30
```

### 2. Реальный клиент Telegram (с поддержкой WEB proxy)

Инструмент стенда (`cd /opt/webproxy/src` перед командами):

```bash
sudo -u webproxy python3 tools/dev/wppdev.py add "Тест 1" --max-devices 2
```

```bash
sudo -u webproxy python3 tools/dev/wppdev.py links 1
```

```bash
sudo -u webproxy python3 tools/dev/wppdev.py qr 1
```

Сценарии (результат записать в FINDINGS.md, раздел «Результаты на VPS»):

1. Ссылка открывается в клиенте с поддержкой WEB proxy, Telegram работает через прокси. Повторить
   на стенде без префикса (`--base-path none`, отдельная установка или другой домен) — ссылка без `%2F`.
2. Второе устройство с **той же** ссылкой не подключается, пока первое онлайн.
   Затем `wppdev.py device-add 1` и `links 1` — второе устройство со своей ссылкой работает одновременно.
3. `wppdev.py disable 1` — клиент теряет соединение за секунды; другой пользователь (`add "Тест 2"`)
   в это время работает без обрывов. `wppdev.py enable 1` — клиент восстанавливается сам.
4. Во время выключения из п. 3, на сервере (остальные клиенты отключены):
   ```bash
   bash /opt/webproxy/src/tools/verify/client-reconnect-watch.sh 120
   ```
   Записать потоков/мин и сессий/мин (FINDINGS п. 6).
5. `reconnect_grace = 60 с` при одной сессии на ссылку (FINDINGS п. 4): на Android свернуть Telegram на
   2–3 минуты и развернуть; переключить Wi‑Fi ↔ мобильную сеть; перезапустить приложение. Записать,
   сколько секунд занимает переподключение и были ли отказы.
6. `wppdev.py rotate <device_id>` — старая ссылка перестаёт работать, новая (`links`) работает.
7. Обслуживание: `wppdev.py maintain` — dirty-слоты получают новые секреты, relay и шарды
   перезапускаются, клиенты переподключаются сами; `status` показывает dirty = 0.
8. `systemctl restart nftables` — таблица `inet wpp` восстанавливается (`nft list table inet wpp`),
   выключенные остаются выключенными, relay и шарды **не** перезапускаются (`systemctl status wpp-relay`
   — время запуска не изменилось), подключённые клиенты не обрываются.

Удалить тестовых пользователей: `wppdev.py list`, затем `wppdev.py delete <id>`.
