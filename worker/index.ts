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
          description: 'Legal timeline management and evidentiary tracking',
          tier: 5,
          domain: 'application',
          ecosystem: 'chittyos',
          endpoints: {
            health: '/api/health',
            cases: '/api/cases',
            timeline: '/api/timeline/entries',
            search: '/api/timeline/search',
            contradictions: '/api/timeline/analysis/contradictions',
          },
          dependencies: ['chittyid', 'chittyconnect', 'chittybeacon'],
        });
      }

      if (path === '/.well-known/mcp-manifest.json') {
        return Response.json({
          schema_version: '1.0',
          name: 'chittychronicle',
          description: 'Legal timeline management MCP tools',
          tools: [
            { name: 'timeline_search', description: 'Search timeline entries' },
            { name: 'case_list', description: 'List legal cases' },
            { name: 'contradiction_detect', description: 'AI contradiction detection' },
          ],
        });
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
