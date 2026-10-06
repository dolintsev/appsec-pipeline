# appsec-pipeline

DevSecOps-пайплайн на GitHub Actions, который при каждом `push` автоматически проверяет учебное уязвимое веб-приложение пятью инструментами безопасности и собирает все находки в формате SARIF во вкладке **Security → Code scanning**.

> ⚠️ Приложение в папке `app/` **специально уязвимо** и предназначено только для обучения. Не запускайте его в открытой сети.

## Схема пайплайна

```
git push
  │
  ├── semgrep ─────────── SAST: анализ исходного кода ──────────────► SARIF
  │
  ├── sca
  │     ├── Syft ──────── SBOM (опись библиотек, CycloneDX) ────────► артефакт
  │     ├── Trivy ─────── уязвимости в библиотеках из SBOM ─────────► SARIF
  │     └── Trivy ─────── ошибки конфигурации Dockerfile ───────────► SARIF
  │
  └── dast
        ├── docker build ─ сборка образа приложения
        ├── Trivy ─────── уязвимости во всём образе (ОС + пакеты) ──► SARIF
        ├── docker run ── запуск приложения на localhost:5000
        ├── Nuclei ────── проверка по своему шаблону ──┐
        └── Dastardly ─── обход сайта и атаки ─────────┴─ to_sarif.py ► SARIF
                                                                        │
                                                 GitHub Security tab ◄──┘
```

Задачи `semgrep`, `sca` и `dast` выполняются параллельно.

## Инструменты

| Этап | Инструмент | Что проверяет | Категория в Security |
|---|---|---|---|
| SAST | [Semgrep](https://semgrep.dev) | Исходный код | `semgrep` |
| SCA | [Syft](https://github.com/anchore/syft) → [Trivy](https://trivy.dev) | Опись библиотек (SBOM) | `trivy-sbom` |
| Конфигурация | Trivy | Dockerfile | `trivy-config` |
| Образ | Trivy | Всё внутри Docker-образа | `trivy-image` |
| DAST | [Nuclei](https://github.com/projectdiscovery/nuclei) | Известные слабости по шаблону | `nuclei` |
| DAST | [Dastardly](https://portswigger.net/burp/dastardly) | Обход сайта и атаки | `dastardly` |

Артефакты каждого запуска: `sbom` (SBOM в формате CycloneDX) и `dast-reports` (исходные отчёты Nuclei и Dastardly).

## Заложенные уязвимости

| Место | Уязвимость | Кто должен найти | Найдено |
|---|---|---|---|
| `app.py:13–14` | Захардкоженный секретный ключ и пароль | Semgrep | <!-- ✅ / ❌ --> |
| `/search` (`app.py:42`) | Отражённый XSS | Semgrep, Dastardly | <!-- ✅ / ❌ --> |
| `/user` (`app.py:50`) | SQL-инъекция | Semgrep | <!-- ✅ / ❌ --> |
| `/ping` (`app.py:58`) | Командная инъекция (`shell=True`) | Semgrep | <!-- ✅ / ❌ --> |
| `/debug` | Открытая страница с секретами | Nuclei | <!-- ✅ / ❌ --> |
| `app.py:70` | Режим отладки Flask | Semgrep | <!-- ✅ / ❌ --> |
| `requirements.txt` | Устаревшие библиотеки с известными CVE | Syft + Trivy | <!-- ✅ / ❌ --> |
| `Dockerfile` | Устаревший базовый образ, запуск от root | Trivy | <!-- ✅ / ❌ --> |

## Результаты

<!-- Заполнить по вкладке Security → Code scanning (фильтр Tool) -->

| Инструмент | Находок | Комментарий |
|---|---|---|
| Semgrep | 13 | Нашёл SQLi, командную инъекцию, debug-режим; одна уязвимость часто даёт несколько находок от разных правил |
| Trivy (SBOM) | | |
| Trivy (Dockerfile) | | |
| Trivy (образ) | | |
| Nuclei | | |
| Dastardly | | |

### Наблюдения

- **Дубликаты.** Командная инъекция в `app.py:58` дала три находки Semgrep от разных правил — без дедупликации (например, в DefectDojo) число находок завышено.
- **Находка сверх ожидаемого.** Semgrep обнаружил XSS в `app.py:59`: вывод команды `ping` вставляется в HTML без экранирования. Этой уязвимости не было в исходном списке.
- **Ложное срабатывание.** `avoid_app_run_with_bad_host` (`0.0.0.0`, `app.py:70`) — в Docker-контейнере прослушивание всех интерфейсов необходимо; доступность определяется пробросом портов.
- **SBOM против образа.** Syft строит SBOM по `requirements.txt` и видит только 5 прямых зависимостей. Сканирование собранного образа Trivy находит также транзитивные зависимости (`urllib3`, `MarkupSafe` и др.) и пакеты ОС.
- <!-- Добавить выводы по Nuclei и Dastardly -->

## Ограничения

- **Привязка DAST-находок.** GitHub Code scanning требует привязки каждой находки к файлу репозитория. Находки Nuclei и Dastardly относятся к URL, поэтому `scripts/to_sarif.py` привязывает их к `app/app.py`, а адрес указывает в тексте находки.
- **Dastardly** не поддерживает SARIF — отчёт JUnit XML переводится скриптом.
- **Версии инструментов** используются через теги `latest`; для стабильного пайплайна их стоит закрепить на конкретных версиях.
- **Нет «гейта»**: пайплайн не блокирует изменения по критичности находок — это следующий шаг развития.

## Структура репозитория

```
appsec-pipeline/
├── .github/workflows/security.yml   # пайплайн
├── app/
│   ├── app.py                       # уязвимое Flask-приложение
│   ├── requirements.txt             # устаревшие зависимости
│   └── Dockerfile
├── nuclei/
│   └── debug-exposure.yaml          # свой шаблон Nuclei
└── scripts/
    └── to_sarif.py                  # Nuclei JSONL / Dastardly JUnit → SARIF
```

## Запуск приложения локально

```bash
cd app
docker build -t vuln-shop .
docker run --rm -p 5000:5000 vuln-shop
```

Приложение будет доступно на `http://localhost:5000`.

## Запуск пайплайна

Автоматически при каждом `push` или вручную: **Actions → Security pipeline → Run workflow**.
