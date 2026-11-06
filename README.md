# Need for Speed: Most Wanted (2005) в браузере

Порт PC-версии *Need for Speed: Most Wanted* (2005) в браузер тем же способом, каким
[th0mk/nfsu2-web](https://github.com/th0mk/nfsu2-web) запускает Underground 2: x86-код игры заранее
переводится в C и собирается в WebAssembly, Direct3D 9 работает через WebGPU, звук через Web Audio.
Игру приносишь свою, в репозитории нет ни её кода, ни данных.

> Не связан с Electronic Arts и не одобрен ею. Форк nfsu2-web (MIT, `LICENSE`), его история сохранена,
> исходный README лежит в [docs/README-nfsu2.md](docs/README-nfsu2.md).

## Состояние

Игра **ещё не запускается**. Сделано всё, что можно сделать без самих exe: инструменты, которые
переносят рантайм U2 на `speed.exe`, и сборка, в которой остаётся только ядро.

| Что | Состояние |
|---|---|
| Лифтер x86 → C (`tools/lift.py`, `genall.py`) | от U2, почти не зависит от игры. Границы кода, `_ftol2` и имя exe теперь берутся из самого exe (`tools/exelayout.py` → `gen/all/layout.h`) |
| Релокации (`tools/reloc2.py`) | умеет обычную таблицу, вариант U2 (безымянная секция) и exe без релокаций (скан данных и операндов: на тестовой DLL нашёл 100% указателей на код) |
| Адреса U2 в рантайме | 981 адрес, из них 373 в ядре MW-сборки (`tools/u2refs.py --core --summary`) |
| Перенос адресов U2 → MW (`tools/sigport.py`) | готов, проверен на настоящих PE (ниже). Ещё не прогонялся на SPEED2.EXE и speed.exe |
| Подстановка в исходники (`tools/applyport.py`) | готова |
| Сборка только ядра (`GAME=mw web/build.sh`) | модули фич U2 выключены, их точки вызова закрыты `runtime/feature_weak.c`. Символы ядра сходятся, wasm ещё не собирался |
| Проверка папки игры (`tools/mwprobe.py`) | готова |

### Насколько можно доверять переносу

`tools/sigport_check.py` берёт две сборки одной DLL и сверяет ответы сигпорта с таблицей экспорта
(сигпорту экспорт не показывают). На 32-битных DLL из Wine:

| Сборки | d3dx9_36 | msvcrt | user32 | kernelbase | wined3d |
|---|---|---|---|---|---|
| 11.13 → 11.18 (один тулчейн) | 98% | 97% | | | 100% |
| 11.7 → 11.18 (один тулчейн, ~5 мес.) | 98% | 97% | 96% | 100% | 97% |
| 11.0 → 11.18 (GCC → clang) | 0% | 0% | 1% | 0% | |

Ошибочных сопоставлений не было ни разу: то, что сигпорт не нашёл, остаётся пустым. Последняя
строка показывает предел: при смене компилятора код не совпадает. U2 (2004) и MW (2005) сделаны
одной студией на одном движке, так что, скорее всего, и одним компилятором. `tools/mwprobe.py`
проверяет это по Rich-заголовкам обоих exe.

## Что нужно, чтобы двинуться дальше

1. **Установленный Most Wanted, а не ISO.** В репаке FreeArc-архивы с SREP, их распаковывает только
   его `setup.exe` под Windows (или CrossOver/Wine). Нужна папка с `speed.exe` и папками `CARS`,
   `FRONTEND`, `GLOBAL`, `TRACKS` и т. д. ASI-моды репака (WidescreenFix, MWFixes, XenonEffects…)
   порт не загружает, мешать они не будут. Мешает только exe, пропатченный на диске или завёрнутый
   в защиту: это покажет `tools/mwprobe.py`.
2. **`SPEED2.EXE` от Underground 2 v1.2 NA**, тот самый (SHA-256 `f9dd86c0…`, см.
   [docs/README-nfsu2.md](docs/README-nfsu2.md)). Все адреса рантайма взяты из него, а пару каждому
   можно найти, только сравнив его код с кодом `speed.exe`. Данные U2 не нужны, хватит одного exe.

## Порядок

```sh
python3 -m venv .venv && .venv/bin/pip install -r requirements.txt

.venv/bin/python tools/mwprobe.py "/путь/к/Most Wanted" "/путь/к/SPEED2.EXE"   # годится ли папка
tools/mwport.sh "/путь/к/SPEED2.EXE" "/путь/к/Most Wanted"            # отчёт: что нашлось, что нет
tools/mwport.sh "/путь/к/SPEED2.EXE" "/путь/к/Most Wanted" --apply    # переписать адреса ядра

web/gen.sh "/путь/к/Most Wanted/speed.exe"    # перевести код MW в C (gen/, в git не идёт)
GAME=mw web/build.sh                           # собрать ядро (нужны wasi-sdk 34 и Rust, см. docs/README-nfsu2.md)
web/start.sh --data "/путь/к/Most Wanted"
```

Всё, что `mwport.sh` не перенёс, перечислено в `out/applyport.txt` по файлам. Эти адреса правятся
руками. Дальше работа такая же, как в nfsu2-web: запускать, смотреть, где игра падает или зависает,
и чинить рантайм по одной проблеме. План по этапам: [docs/MW_PORT.md](docs/MW_PORT.md).

## Устройство

- `tools/`: лифтер (Capstone) и инструменты переноса: `u2refs.py`, `sigport.py`, `applyport.py`,
  `mwprobe.py`, `exelayout.py`, `mwport.sh`. Тесты: `tools/test_sigport.py`, `tools/sigport_check.py`.
- `runtime/`: Windows, Direct3D 9, DirectSound, DirectInput, переписанные заново. Модули ядра для MW
  перечислены в `tools/mw_core.txt`, остальные относятся к фичам U2.
- `web/`: страница (WebGPU, AudioWorklet, воркеры) и сервер на Rust.

## Благодарности

Проект целиком стоит на [nfsu2-web](https://github.com/th0mk/nfsu2-web) (th0mk) и
[NFSU2Recomp](https://github.com/TalhaMudo/NFSU2Recomp) (Talha Müderrisoğlu), а те, в свою очередь, на
[N64: Recompiled](https://github.com/N64Recomp/N64Recomp) и [XenonRecomp](https://github.com/hedge-dev/XenonRecomp).
