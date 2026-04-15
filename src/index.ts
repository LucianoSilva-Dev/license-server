import 'dotenv/config';
import fastify from 'fastify';
import { v4 as uuidv4 } from 'uuid';
import { publicRoutes, adminRoutes } from './routes.js';
import { getDb } from './db.js';

const PORT = process.env.PORT ? parseInt(process.env.PORT) : 3001;

let ADMIN_SECRET = process.env.ADMIN_SECRET || '';

export const app = fastify({ logger: false });

app.register(publicRoutes);
app.register(adminRoutes);

async function bootstrap() {
    getDb();

    if (!ADMIN_SECRET) {
        ADMIN_SECRET = uuidv4().replace(/-/g, '');
        process.env.ADMIN_SECRET = ADMIN_SECRET;
        console.log('');
        console.log('=================================================');
        console.log('  ADMIN_SECRET gerado automaticamente:');
        console.log(`  ${ADMIN_SECRET}`);
        console.log('  Salve no .env para persistir entre restarts.');
        console.log('=================================================');
        console.log('');
    }

    await app.listen({ port: PORT, host: '0.0.0.0' });
    console.log(`License server rodando na porta ${PORT}`);
}

bootstrap().catch((err) => {
    console.error('Falha ao iniciar:', err);
    process.exit(1);
});
