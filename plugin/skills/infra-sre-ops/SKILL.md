---
name: infra-sre-ops
description: Read-only-first incident diagnostics, resource analysis, and infrastructure/database/security inspection across Proxmox VE, Kubernetes/k3s, Nomad, Docker, Zabbix, Grafana/Prometheus/Loki, PostgreSQL, MSSQL, Linux/Windows SSH, and Trivy.
---

# Infrastructure, DevOps & SRE Diagnostics Playbook

Единый протокол диагностики инцидентов, анализа ресурсов, оптимизации и безопасности инфраструктуры.

## 1. Железный инвариант безопасности

- **Все инфраструктурные и БД-серверы настроены в Read-Only по умолчанию** через `mcp_env_exec.py` и `mcp-gate.env`.
- Диагностику, сбор фактов, логов, метрик и планов (`EXPLAIN`, `plan_job`, `nomad job validate`) выполняйте автономно.
- **Любые мутации** (рестарт/удаление VM/LXC/подов/джобов, DDL/DML в БД, правка firewall/ACL/Zabbix/Nomad, перезапись конфигов на серверах) выполняйте **только после явного подтверждения пользователя**, показав точный план и риск.

## 2. Матрица инструментов по слоям инфраструктуры

| Слой | Инструмент | Что диагностировать | Статус / Подключение |
| :--- | :--- | :--- | :--- |
| **Security / IaC / SCA** | **`trivy` MCP** + `semgrep` MCP | CVE в зависимостях/образах, ошибки Dockerfile/K8s/Terraform/HCL, секреты, SBOM | Активен сразу (0 кредов) |
| **Nomad (Charon)** | `nomad` CLI + **`nomad` MCP** | Офлайн `nomad job validate`; живые jobs, allocations, logs, nodes, `parse_job_hcl`, `plan_job` (RO, `variables` закрыты) | CLI активен; MCP ждёт `NOMAD_ADDR`/`NOMAD_TOKEN` |
| **Charon Observability** | **`grafana` MCP** (`--disable-write`) | Дашборды Grafana, PromQL (вкл. Blackbox `probe_success`), Loki LogQL, Alloy label-анализ, алерты | Ждёт `GRAFANA_URL` + `GRAFANA_SERVICE_ACCOUNT_TOKEN` |
| **Kubernetes / k3s / KAS** | **`kubernetes` MCP** (`k8s-mcp.toml`) | Контексты (вкл. GitLab KAS), pods/events/logs, Helm releases, квоты (RO, `Secret` запрещён) | Ждёт `~/.kube/config` или `KUBECONFIG` |
| **Proxmox VE** | **`proxmox` MCP** (`TOOL_ROUTING=true`) | Ноды, QEMU VM, LXC, storage/ZFS/thin-pool, **RRD-метрики** CPU/RAM/disk/net, задачи/бэкапы | Ждёт `PROXMOX_*` (напр. `192.168.0.39:8006`, токен `PVEAuditor`) |
| **Zabbix 6/7/8** | **`zabbix` MCP** (RO + whitelist) | Активные проблемы, триггеры, события, items, history/trends, хосты | Ждёт `ZABBIX_URL` + `ZABBIX_TOKEN` |
| **PostgreSQL** | **`postgres` MCP** (`@bytebase/dbhub`, `readonly = true`) | `search_objects`, `execute_sql` (`EXPLAIN`, `pg_stat_statements`, индексы, `max_rows = 200`) | Ждёт `~/.gemini/secrets/dbhub-pg.toml` (см. `dbhub-pg.toml.example`) |
| **MSSQL** | **`mssql` MCP** (`MSSQL_READ_ONLY=true`) | Схемы, `mssql_performance_health`, `mssql_get_deadlocks`, фрагментация и анализ индексов | Ждёт `MSSQL_*` |
| **Linux/Win Server & Docker** | **`ssh` MCP** (`ssh-mcp-ro.toml`, роль `viewer`) / `ssh` CLI | Системные сервисы (`systemd`, Event Log), диски/память/сеть, удалённый `docker ps`/`logs`/`inspect`/`stats` | Ждёт `~/.gemini/config/ssh-mcp-ro.toml` (см. `ssh-mcp-ro.toml.example`) |
| **Лог-аналитика** | **`duckdb` MCP** (read-only БД) | SQL-агрегация по выгруженным JSON/NDJSON/CSV логам, метрикам и таймлайнам | Активен сразу (0 кредов) |

## 3. Алгоритм расследования инцидента

1. **Симптом → Метрики и алерты:** проверьте Zabbix / Grafana (PromQL + Loki) или системные логи по SSH.
2. **Оркестратор и рантайм:** проверьте состояние Nomad allocations / Kubernetes pods / Docker контейнеров / Proxmox LXC/VM + RRD-графики (CPU steal, OOM, ZFS/thin-pool, диск).
3. **Слой данных:** при медленных запросах или блокировках — `postgres` (`search_objects`, read-only `execute_sql` с `EXPLAIN` / `pg_stat_statements`) или `mssql` (`mssql_get_deadlocks`, `mssql_performance_health`).
4. **Связь с кодом и деплоем:** сопоставьте таймлайн инцидента с недавними MR/pipelines в `gitlab` MCP и цепочкой вызовов в `codebase-memory`.
5. **Если нужный MCP сейчас `disabled: true`:** проверьте наличие ключей в `C:\Users\in\.gemini\secrets\mcp-gate.env` (по шаблону `mcp-gate.env.example`), не падайте молча — либо выполните безопасную read-only диагностику через доступный `ssh`/CLI, либо сообщите пользователю, какой именно ключ/доступ разблокирует прямую интеграцию.
