import type { FastifyPluginAsync } from 'fastify';
import { createKey, getKeyByValue, listAllKeys, updateKey, deleteKey, maskKey, getDb } from './db.js';

const ADMIN_SECRET = process.env.ADMIN_SECRET || '';

export const publicRoutes: FastifyPluginAsync = async (server) => {
    server.get<{ Params: { key: string } }>('/v/:key', async (request, reply) => {
        const { key } = request.params;

        const record = getKeyByValue(key);

        if (!record) {
            return reply.code(200).send({ valid: false, reason: 'invalid' });
        }

        if (record.status === 'revoked') {
            return reply.code(200).send({ valid: false, reason: 'revoked' });
        }

        if (record.expires_at && new Date(record.expires_at) < new Date()) {
            return reply.code(200).send({ valid: false, reason: 'expired' });
        }

        if (record.status === 'active') {
            return reply.code(200).send({ valid: true });
        }

        return reply.code(200).send({ valid: false, reason: 'invalid' });
    });
};

export const adminRoutes: FastifyPluginAsync = async (server) => {
    server.addHook('onRequest', async (request, reply) => {
        const auth = request.headers.authorization;
        if (!auth || auth !== `Bearer ${ADMIN_SECRET}`) {
            return reply.code(401).send({ error: 'Nao autorizado' });
        }
    });

    server.get('/admin/secret', async () => {
        return { secret: ADMIN_SECRET };
    });

    server.post('/admin/keys', async (request, reply) => {
        const body = request.body as { label?: string; expires_at?: string };
        if (!body?.label) {
            return reply.code(400).send({ error: 'Campo "label" e obrigatorio' });
        }
        const record = createKey(body.label, body.expires_at);
        return reply.code(201).send(record);
    });

    server.get('/admin/keys', async () => {
        const keys = listAllKeys();
        return keys.map((k) => ({
            ...k,
            key: maskKey(k.key),
            _full_key: undefined,
        }));
    });

    server.get<{ Params: { id: string } }>('/admin/keys/:id', async (request, reply) => {
        const id = parseInt(request.params.id, 10);
        const d = getDb();
        const record = d.prepare('SELECT * FROM license_keys WHERE id = ?').get(id);
        if (!record) {
            return reply.code(404).send({ error: 'Chave nao encontrada' });
        }
        return { ...record, key: maskKey((record as any).key) };
    });

    server.patch<{ Params: { id: string } }>('/admin/keys/:id', async (request, reply) => {
        const id = parseInt(request.params.id, 10);
        const body = request.body as { label?: string; status?: 'active' | 'revoked' | 'expired'; expires_at?: string | null };
        const record = updateKey(id, body as any);
        if (!record) {
            return reply.code(404).send({ error: 'Chave nao encontrada' });
        }
        return { ...record, key: maskKey(record.key) };
    });

    server.delete<{ Params: { id: string } }>('/admin/keys/:id', async (request, reply) => {
        const id = parseInt(request.params.id, 10);
        const deleted = deleteKey(id);
        if (!deleted) {
            return reply.code(404).send({ error: 'Chave nao encontrada' });
        }
        return reply.code(204).send();
    });
};
