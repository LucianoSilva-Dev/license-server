import type { FastifyPluginAsync } from 'fastify';
import { createKey, getKeyByValue, listAllKeys, updateKey, deleteKey, maskKey, getDb } from './db.js';

const ADMIN_SECRET = process.env.ADMIN_SECRET || '';

export const publicRoutes: FastifyPluginAsync = async (server) => {
    server.get<{
        Params: { key: string };
    }>('/v/:key', {
        schema: {
            tags: ['Validação'],
            summary: 'Validar uma chave de licença',
            description: 'Verifica se uma chave de licença é válida, não está revogada e não está expirada.',
            params: {
                type: 'object',
                required: ['key'],
                properties: {
                    key: { type: 'string', description: 'Chave de licença' },
                },
            },
            response: {
                200: {
                    type: 'object',
                    properties: {
                        valid: { type: 'boolean' },
                        reason: { type: 'string', enum: ['invalid', 'revoked', 'expired'] },
                    },
                },
            },
        },
    }, async (request, reply) => {
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

    server.get('/admin/secret', {
        schema: {
            tags: ['Admin'],
            summary: 'Obter secret de administração',
            description: 'Retorna o ADMIN_SECRET atualmente em uso.',
            security: [{ bearerAuth: [] }],
            response: {
                200: {
                    type: 'object',
                    properties: {
                        secret: { type: 'string' },
                    },
                },
                401: {
                    type: 'object',
                    properties: {
                        error: { type: 'string' },
                    },
                },
            },
        },
    }, async () => {
        return { secret: ADMIN_SECRET };
    });

    server.post('/admin/keys', {
        schema: {
            tags: ['Admin - Chaves'],
            summary: 'Criar nova chave de licença',
            description: 'Cria uma nova chave de licença com um label opcional e data de expiração.',
            security: [{ bearerAuth: [] }],
            body: {
                type: 'object',
                required: ['label'],
                properties: {
                    label: { type: 'string', description: 'Identificador descritivo da chave' },
                    expires_at: { type: 'string', format: 'date-time', description: 'Data de expiração (ISO 8601)' },
                },
            },
            response: {
                201: {
                    type: 'object',
                    properties: {
                        id: { type: 'number' },
                        key: { type: 'string' },
                        label: { type: 'string' },
                        status: { type: 'string' },
                        expires_at: { type: 'string', nullable: true },
                        created_at: { type: 'string' },
                    },
                },
                400: {
                    type: 'object',
                    properties: {
                        error: { type: 'string' },
                    },
                },
            },
        },
    }, async (request, reply) => {
        const body = request.body as { label?: string; expires_at?: string };
        if (!body?.label) {
            return reply.code(400).send({ error: 'Campo "label" e obrigatorio' });
        }
        const record = createKey(body.label, body.expires_at);
        return reply.code(201).send(record);
    });

    server.get('/admin/keys', {
        schema: {
            tags: ['Admin - Chaves'],
            summary: 'Listar todas as chaves',
            description: 'Retorna todas as chaves de licença cadastradas (com a chave mascarada).',
            security: [{ bearerAuth: [] }],
            response: {
                200: {
                    type: 'array',
                    items: {
                        type: 'object',
                        properties: {
                            id: { type: 'number' },
                            key: { type: 'string' },
                            label: { type: 'string' },
                            status: { type: 'string' },
                            expires_at: { type: 'string', nullable: true },
                            created_at: { type: 'string' },
                        },
                    },
                },
            },
        },
    }, async () => {
        const keys = listAllKeys();
        return keys.map((k) => ({
            ...k,
            key: maskKey(k.key),
            _full_key: undefined,
        }));
    });

    server.get<{
        Params: { id: string };
    }>('/admin/keys/:id', {
        schema: {
            tags: ['Admin - Chaves'],
            summary: 'Buscar chave por ID',
            description: 'Retorna os dados de uma chave de licença específica.',
            security: [{ bearerAuth: [] }],
            params: {
                type: 'object',
                required: ['id'],
                properties: {
                    id: { type: 'string', description: 'ID da chave' },
                },
            },
            response: {
                200: {
                    type: 'object',
                    properties: {
                        id: { type: 'number' },
                        key: { type: 'string' },
                        label: { type: 'string' },
                        status: { type: 'string' },
                        expires_at: { type: 'string', nullable: true },
                        created_at: { type: 'string' },
                    },
                },
                404: {
                    type: 'object',
                    properties: {
                        error: { type: 'string' },
                    },
                },
            },
        },
    }, async (request, reply) => {
        const id = parseInt(request.params.id, 10);
        const d = getDb();
        const record = d.prepare('SELECT * FROM license_keys WHERE id = ?').get(id);
        if (!record) {
            return reply.code(404).send({ error: 'Chave nao encontrada' });
        }
        return { ...record, key: maskKey((record as any).key) };
    });

    server.patch<{
        Params: { id: string };
    }>('/admin/keys/:id', {
        schema: {
            tags: ['Admin - Chaves'],
            summary: 'Atualizar chave de licença',
            description: 'Atualiza parcialmente os dados de uma chave de licença (label, status, expires_at).',
            security: [{ bearerAuth: [] }],
            params: {
                type: 'object',
                required: ['id'],
                properties: {
                    id: { type: 'string', description: 'ID da chave' },
                },
            },
            body: {
                type: 'object',
                properties: {
                    label: { type: 'string', description: 'Novo label' },
                    status: { type: 'string', enum: ['active', 'revoked', 'expired'], description: 'Novo status' },
                    expires_at: { type: 'string', nullable: true, description: 'Nova data de expiração (null para remover)' },
                },
            },
            response: {
                200: {
                    type: 'object',
                    properties: {
                        id: { type: 'number' },
                        key: { type: 'string' },
                        label: { type: 'string' },
                        status: { type: 'string' },
                        expires_at: { type: 'string', nullable: true },
                        created_at: { type: 'string' },
                    },
                },
                404: {
                    type: 'object',
                    properties: {
                        error: { type: 'string' },
                    },
                },
            },
        },
    }, async (request, reply) => {
        const id = parseInt(request.params.id, 10);
        const body = request.body as { label?: string; status?: 'active' | 'revoked' | 'expired'; expires_at?: string | null };
        const record = updateKey(id, body as any);
        if (!record) {
            return reply.code(404).send({ error: 'Chave nao encontrada' });
        }
        return { ...record, key: maskKey(record.key) };
    });

    server.delete<{
        Params: { id: string };
    }>('/admin/keys/:id', {
        schema: {
            tags: ['Admin - Chaves'],
            summary: 'Deletar chave de licença',
            description: 'Remove permanentemente uma chave de licença.',
            security: [{ bearerAuth: [] }],
            params: {
                type: 'object',
                required: ['id'],
                properties: {
                    id: { type: 'string', description: 'ID da chave' },
                },
            },
            response: {
                204: {
                    type: 'null',
                    description: 'Chave deletada com sucesso',
                },
                404: {
                    type: 'object',
                    properties: {
                        error: { type: 'string' },
                    },
                },
            },
        },
    }, async (request, reply) => {
        const id = parseInt(request.params.id, 10);
        const deleted = deleteKey(id);
        if (!deleted) {
            return reply.code(404).send({ error: 'Chave nao encontrada' });
        }
        return reply.code(204).send();
    });
};
