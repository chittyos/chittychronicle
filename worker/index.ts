// Cloudflare Worker entry for ChittyChronicle
// Edge health/manifest layer — full app runs Express+Vite on Neon PostgreSQL

interface Env {
  NEON_DATABASE_URL: string;
  CHITTYCONNECT_SERVICE_TOKEN: string;
  ENVIRONMENT: string;
}

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url);
    const path = url.pathname;

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
      if (path === '/api/health' || path === '/health') {
        return Response.json({
          status: 'ok',
          service: 'chittychronicle',
          edge: true,
          environment: env.ENVIRONMENT,
          timestamp: new Date().toISOString(),
        });
      }

      if (path === '/.well-known/chronicle-manifest.json' || path === '/.well-known/service-manifest.json') {
        return Response.json({
          service: 'chittychronicle',
          version: '1.0.0',
          description: 'ChittyChronicle edge discovery and health surface',
          tier: 5,
          domain: 'application',
          ecosystem: 'chittyos',
          endpoints: {
            health: '/api/health',
            serviceManifest: '/.well-known/service-manifest.json',
            chronicleManifest: '/.well-known/chronicle-manifest.json',
            mcpManifest: '/.well-known/mcp-manifest.json',
          },
          applicationApi: {
            status: 'not-routed',
            canonicalEventPath: '/api/v1/events',
          },
          dependencies: ['chittyid', 'chittyconnect', 'chittybeacon'],
        });
      }

      if (path === '/.well-known/mcp-manifest.json') {
        return Response.json({
          schema_version: '1.0',
          name: 'chittychronicle',
          description: 'ChittyChronicle edge discovery surface; application MCP tools are not routed here',
          available: false,
          reason: 'application_api_not_routed',
          tools: [],
        });
      }

      if (path === '/events' || path === '/api/v1/log' || path.startsWith('/api/v1/events') ||
          path.startsWith('/api/cases') || path.startsWith('/api/timeline')) {
        return Response.json(
          {
            error: 'ChittyChronicle application API is not routed through this edge Worker',
            code: 'APPLICATION_API_NOT_ROUTED',
            service: 'chittychronicle',
            canonicalEventPath: '/api/v1/events',
            path,
          },
          { status: 503 }
        );
      }

      return Response.json(
        { error: 'Not found', service: 'chittychronicle', path },
        { status: 404 }
      );
    } catch (error) {
      console.error('ChittyChronicle edge error:', error);
      return Response.json(
        { error: 'Internal server error', message: error instanceof Error ? error.message : 'Unknown error' },
        { status: 500 }
      );
    }
  },
} satisfies ExportedHandler<Env>;
