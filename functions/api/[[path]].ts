// Cloudflare Workers edge handler for ChittyChronicle
// Lightweight proxy/health layer — main app runs Express+Vite on Neon PostgreSQL

interface Env {
  NEON_DATABASE_URL: string;
  CHITTYCONNECT_SERVICE_TOKEN: string;
  ENVIRONMENT: string;
}

export async function onRequest(context: {
  request: Request;
  env: Env;
  params: { path: string[] };
}): Promise<Response> {
  const { request, env, params } = context;
  const path = params.path?.join('/') || '';

  if (request.method === 'OPTIONS') {
    return new Response(null, {
      headers: {
        'Access-Control-Allow-Origin': '*',
        'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
        'Access-Control-Allow-Headers': 'Content-Type, Authorization',
      },
    });
  }

  try {
    if (path === 'health') {
      return Response.json({
        status: 'ok',
        service: 'chittychronicle',
        edge: true,
        environment: env.ENVIRONMENT,
        timestamp: new Date().toISOString(),
      });
    }

    if (path === 'manifest' || path === '') {
      return Response.json({
        service: 'chittychronicle',
        version: '1.0.0',
        description: 'Legal timeline management and evidentiary tracking',
        endpoints: ['/api/health', '/api/cases', '/api/timeline/entries', '/api/timeline/search'],
        ecosystem: 'chittyos',
        tier: 5,
      });
    }

    return Response.json({ error: 'Endpoint not found', path: `/api/${path}` }, { status: 404 });
  } catch (error) {
    console.error('API Error:', error);
    return Response.json(
      { error: 'Internal server error', message: error instanceof Error ? error.message : 'Unknown error' },
      { status: 500 }
    );
  }
}
