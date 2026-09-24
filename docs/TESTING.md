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
