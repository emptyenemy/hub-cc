#!/usr/bin/env node
/*
 * refresh-models-cache.js — снять каталог моделей шлюза и положить его в
 * routing/custom-models-cache.json, то есть в тот снимок, по которому дашборд
 * (health-catalog.js) отвечает на вопрос «какие модели у шлюза есть».
 *
 * Зачем отдельный файл, а не кнопка в дашборде. Кеш наполняет сканер
 * КАСТОМ-ПРОВАЙДЕРОВ, и только для baseUrl, заведённых во вкладке «Кастом»
 * (transparent-proxy.js:5350, health-catalog.js:663). У AgentRouter такой записи
 * нет, поэтому его каталог пуст, и хаб честно пишет: «каталогов на диске нет,
 * есть только пожелание тир-карты» — на вопрос «какие модели шлюз отдаёт» ответа
 * с диска не было ни одного.
 *
 * 🪤 Ключ записи — URL, а не имя шлюза: health-catalog сопоставляет каталог шлюзу
 * по ХОСТУ (`bkByHost.get(hostOf(base))`), поэтому хост в этом URL обязан
 * совпадать с `host` из реестра MONEY_GW (у AgentRouter это agentrouter.org).
 * Запись с чужим хостом молча уедет в bk=custom и останется невидимой.
 *
 * Запуск:
 *   node tools/refresh-models-cache.js                 # agentrouter, ключ из пула
 *   node tools/refresh-models-cache.js https://agentrouter.org/v1 --key=sk-...
 *
 * Заголовки — как у прокси (CC_FALLBACK_HEADERS в keepalive-proxy.js): на «голый»
 * запрос AgentRouter отвечает 401 «unauthorized client detected», а с ними отдаёт
 * список моделей. Свежесть: health-catalog считает каталог протухшим через 7 дней,
 * и это правильно — 03.09 justwoker молча убрал модель, и 255 запросов легли.
 */
'use strict';

const fs = require('fs');
const path = require('path');
const { writeJsonSync } = require('../routing/lib/durable-write.js');

const ROUTING = path.join(__dirname, '..', 'routing');
const CACHE_FILE = path.join(ROUTING, 'custom-models-cache.json');
const POOL_FILE = path.join(ROUTING, 'agentrouter-sessions.json');

const DEFAULT_BASE = 'https://agentrouter.org/v1';

// Те же заголовки, что шлёт прокси: без них шлюз отвечает 401 на /v1/models.
const CC_HEADERS = {
    'user-agent': 'claude-cli/2.1.158 (external, sdk-cli)',
    'anthropic-version': '2023-06-01',
    'x-app': 'cli',
    accept: 'application/json',
};

function activePoolKey() {
    try {
        const pool = JSON.parse(fs.readFileSync(POOL_FILE, 'utf8'));
        const act = (Array.isArray(pool) ? pool : []).find(a => a && a.active && a.api_key);
        return act ? act.api_key : null;
    } catch { return null; }
}

function loadCache() {
    try {
        const raw = fs.readFileSync(CACHE_FILE, 'utf8');
        const obj = JSON.parse(raw.charCodeAt(0) === 0xFEFF ? raw.slice(1) : raw);
        return obj && typeof obj === 'object' ? obj : {};
    } catch { return {}; }
}

async function main() {
    const args = process.argv.slice(2);
    const base = (args.find(a => !a.startsWith('--')) || DEFAULT_BASE).replace(/\/+$/, '');
    const keyArg = (args.find(a => a.startsWith('--key=')) || '').slice(6);
    const key = keyArg || activePoolKey();
    if (!key) {
        console.error('нет ключа: ни --key, ни активного аккаунта в пуле');
        process.exit(1);
    }

    const res = await fetch(base + '/models', { headers: Object.assign({ Authorization: `Bearer ${key}` }, CC_HEADERS) });
    const text = await res.text();
    if (!res.ok) {
        console.error(`шлюз ответил ${res.status}: ${text.slice(0, 200)}`);
        process.exit(2);
    }
    let doc;
    try { doc = JSON.parse(text); } catch (e) {
        console.error(`ответ не JSON (${e.message}): ${text.slice(0, 120)}`);
        process.exit(2);
    }
    const list = Array.isArray(doc.data) ? doc.data : (Array.isArray(doc.models) ? doc.models : []);
    const models = list.map(m => ({ id: m.id || m.name, owned_by: m.owned_by || '' })).filter(m => m.id);
    if (!models.length) {
        console.error('шлюз вернул пустой список — запись не пишу (пустой каталог хуже отсутствующего)');
        process.exit(2);
    }

    const cache = loadCache();
    cache[base] = { data: models, ts: Date.now() };
    writeJsonSync(CACHE_FILE, cache);

    console.log(`каталог ${new URL(base).hostname}: ${models.length} моделей → ${path.relative(process.cwd(), CACHE_FILE)}`);
    for (const m of models) console.log(`  ${m.id}${m.owned_by ? ` (${m.owned_by})` : ''}`);
}

main().catch(e => { console.error('сбой:', e.message); process.exit(3); });
