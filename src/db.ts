import Database from 'better-sqlite3';
import path from 'node:path';
import fs from 'node:fs';
import { v4 as uuidv4 } from 'uuid';

const DB_PATH = process.env.DB_PATH || path.resolve('data/licenses.sqlite');

let db: Database.Database;

export interface LicenseKey {
    id: number;
    key: string;
    label: string;
    status: 'active' | 'revoked' | 'expired';
    expires_at: string | null;
    created_at: string;
}

export function getDb(): Database.Database {
    if (!db) {
        const dir = path.dirname(DB_PATH);
        if (!fs.existsSync(dir)) {
            fs.mkdirSync(dir, { recursive: true });
        }
        db = new Database(DB_PATH);
        db.pragma('journal_mode = WAL');
        initSchema();
    }
    return db;
}

function initSchema() {
    db.exec(`
        CREATE TABLE IF NOT EXISTS license_keys (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            key        TEXT UNIQUE NOT NULL,
            label      TEXT NOT NULL,
            status     TEXT NOT NULL DEFAULT 'active',
            expires_at TEXT,
            created_at TEXT NOT NULL DEFAULT (datetime('now'))
        )
    `);
}

export function createKey(label: string, expiresAt?: string): LicenseKey {
    const d = getDb();
    const key = uuidv4().replace(/-/g, '');
    const stmt = d.prepare('INSERT INTO license_keys (key, label, expires_at) VALUES (?, ?, ?)');
    const info = stmt.run(key, label, expiresAt ?? null);
    return d.prepare('SELECT * FROM license_keys WHERE id = ?').get(info.lastInsertRowid) as LicenseKey;
}

export function getKeyByValue(key: string): LicenseKey | undefined {
    const d = getDb();
    return d.prepare('SELECT * FROM license_keys WHERE key = ?').get(key) as LicenseKey | undefined;
}

export function listAllKeys(): LicenseKey[] {
    const d = getDb();
    return d.prepare('SELECT * FROM license_keys ORDER BY created_at DESC').all() as LicenseKey[];
}

export function updateKey(id: number, updates: Partial<Pick<LicenseKey, 'label' | 'status' | 'expires_at'>>): LicenseKey | undefined {
    const d = getDb();
    const fields: string[] = [];
    const values: any[] = [];

    if (updates.label !== undefined) { fields.push('label = ?'); values.push(updates.label); }
    if (updates.status !== undefined) { fields.push('status = ?'); values.push(updates.status); }
    if (updates.expires_at !== undefined) { fields.push('expires_at = ?'); values.push(updates.expires_at); }

    if (fields.length === 0) return d.prepare('SELECT * FROM license_keys WHERE id = ?').get(id) as LicenseKey | undefined;

    values.push(id);
    d.prepare(`UPDATE license_keys SET ${fields.join(', ')} WHERE id = ?`).run(...values);
    return d.prepare('SELECT * FROM license_keys WHERE id = ?').get(id) as LicenseKey | undefined;
}

export function deleteKey(id: number): boolean {
    const d = getDb();
    const info = d.prepare('DELETE FROM license_keys WHERE id = ?').run(id);
    return info.changes > 0;
}

export function maskKey(key: string): string {
    if (key.length <= 8) return '****';
    return key.slice(0, 4) + '****' + key.slice(-4);
}
