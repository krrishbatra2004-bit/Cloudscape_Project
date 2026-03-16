import json
import logging
import asyncio
from typing import Dict, Any, List
from aiohttp import web  # type: ignore
from pathlib import Path
import os
import sys
import datetime
from neo4j.time import DateTime, Date, Time  # type: ignore

# Add src to path if needed
sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))

from src.core.config import config  # type: ignore
from src.utils.logger import get_logger  # type: ignore

logger = get_logger("Cloudscape.API")

class CloudscapeApiServer:
    def __init__(self):
        self.app = web.Application()
        self.setup_routes()
        self._runner = None
        self._site = None
        self._driver = None
        
    def setup_routes(self):
        # Enable permissive CORS for frontend Vite dev server (localhost:5176)
        self.app.add_routes([
            web.options('/api/{tail:.*}', self.handle_cors_preflight),
            web.get('/api/graph', self.get_graph),
            web.get('/api/assets', self.get_assets),
            web.get('/api/blast-radius/{node_id}', self.get_blast_radius),
            web.get('/api/timeline', self.get_timeline),
            web.get('/api/timeline/{snapshot_id}', self.get_timeline_snapshot),
            web.get('/api/events', self.get_events)
        ])
        
        # Add CORS headers to all responses
        self.app.middlewares.append(self.cors_middleware)

    @web.middleware
    async def cors_middleware(self, request, handler):
        response = await handler(request)
        response.headers['Access-Control-Allow-Origin'] = '*'
        response.headers['Access-Control-Allow-Methods'] = 'GET, POST, OPTIONS'
        response.headers['Access-Control-Allow-Headers'] = 'Content-Type, Authorization'
        return response

    async def handle_cors_preflight(self, request):
        return web.Response(headers={
            'Access-Control-Allow-Origin': '*',
            'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
            'Access-Control-Allow-Headers': 'Content-Type, Authorization',
        })

    async def _get_neo4j_session(self):
        if not self._driver:
            from neo4j import AsyncGraphDatabase  # type: ignore
            uri = config.settings.database.neo4j_uri
            user = config.settings.database.neo4j_user
            password = config.settings.database.neo4j_password
            self._driver = AsyncGraphDatabase.driver(uri, auth=(user, password))
        return self._driver.session()  # type: ignore

    async def get_graph(self, request):
        """Returns the full cloud topology graph matching the React frontend format."""
        query = """
        MATCH (n:Resource)
        OPTIONAL MATCH (n)-[r]->(m:Resource)
        RETURN collect(DISTINCT n) as nodes, collect(DISTINCT {source: n.arn, target: m.arn, type: type(r)}) as edges
        """
        try:
            session = await self._get_neo4j_session()
            async with session as s:  # type: ignore
                result = await s.run(query)
                records = await result.fetch(1)
                
                if not records:
                    return web.json_response({"nodes": [], "edges": []})
                    
                record = records[0]
                
                # Format Nodes
                raw_nodes = record.get("nodes", [])
                formatted_nodes = []
                for n_obj in raw_nodes:
                    # In python neo4j driver, properties are accessed dictionary style
                    props = dict(n_obj.items())
                    
                    # Force clean properties of DateTimes
                    clean_props: Dict[str, Any] = {}
                    for k, v in props.items():
                        if isinstance(v, (datetime.datetime, datetime.date, datetime.time)):
                            clean_props[k] = v.isoformat()
                        elif isinstance(v, (DateTime, Date, Time)):
                            if hasattr(v, 'iso_format'):
                                clean_props[k] = v.iso_format()  # type: ignore
                            else:
                                clean_props[k] = str(v)
                        else:
                            clean_props[k] = v

                    formatted_nodes.append({
                        "id": clean_props.get("arn", clean_props.get("id", "Unknown")),
                        "name": clean_props.get("name", clean_props.get("arn", "Unknown")),
                        "type": clean_props.get("type", "unknown"),
                        "provider": clean_props.get("cloud_provider", "unknown"),
                        "riskScore": float(clean_props.get("risk_score", 0.0)),
                        "permissions": [], # Mock or unroll if needed
                        "metadata": clean_props
                    })
                
                # Format Edges - filter null targets
                raw_edges = record.get("edges", [])
                edges = [e for e in raw_edges if e and e.get("target")]
                
                return web.json_response({
                    "nodes": formatted_nodes,
                    "edges": edges
                })
                
        except Exception as e:
            logger.error(f"Failed to fetch graph: {e}")
            return web.json_response({"error": str(e)}, status=500)

    async def get_assets(self, request):
        """Returns a flat list of assets."""
        try:
            # Reuses the exact graph aggregation logic to pull nodes for the table
            resp = await self.get_graph(request)
            data = json.loads(resp.text)  # type: ignore
            return web.json_response({"assets": data.get("nodes", [])})
        except Exception as e:
            logger.error(f"Failed to fetch assets: {e}")
            return web.json_response({"error": str(e)}, status=500)

    async def get_blast_radius(self, request):
        """Returns downstream impacted assets from a given node."""
        node_id = request.match_info['node_id']
        query = """
        MATCH (src:Resource {arn: $node_id})-[r*1..3]->(impacted:Resource)
        RETURN collect(DISTINCT impacted) as nodes, 
               collect(DISTINCT {source: startNode(last(r)).arn, target: endNode(last(r)).arn, type: type(last(r))}) as edges
        """
        try:
            session = await self._get_neo4j_session()
            async with session as s:  # type: ignore
                result = await s.run(query, node_id=node_id)
                records = await result.fetch(1)
                
                if not records:
                    return web.json_response({"nodes": [], "edges": []})
                    
                record = records[0]
                
                formatted_nodes = []
                for n_obj in record.get("nodes", []):
                    props = dict(n_obj.items())
                    
                    clean_props: Dict[str, Any] = {}
                    for k, v in props.items():
                        if isinstance(v, (datetime.datetime, datetime.date, datetime.time)):
                            clean_props[k] = v.isoformat()
                        elif isinstance(v, (DateTime, Date, Time)):
                            if hasattr(v, 'iso_format'):
                                clean_props[k] = v.iso_format()  # type: ignore
                            else:
                                clean_props[k] = str(v)
                        else:
                            clean_props[k] = v

                    formatted_nodes.append({
                        "id": clean_props.get("arn", clean_props.get("id", "Unknown")),
                        "name": clean_props.get("name", clean_props.get("arn", "Unknown")),
                        "type": clean_props.get("type", "unknown"),
                        "provider": clean_props.get("cloud_provider", "unknown"),
                        "riskScore": float(clean_props.get("risk_score", 0.0)),
                    })
                
                edges = [e for e in record.get("edges", []) if e and e.get("target")]
                
                # Calculate aggregate risk
                total_risk = sum(n["riskScore"] for n in formatted_nodes)
                overall_risk = total_risk / len(formatted_nodes) if formatted_nodes else 0
                
                return web.json_response({
                    "nodes": formatted_nodes,
                    "edges": edges,
                    "metrics": {
                        "totalAssetsImpacted": len(formatted_nodes),
                        "overallRisk": round(float(overall_risk), 2),  # type: ignore
                        "criticalPaths": len([n for n in formatted_nodes if n["riskScore"] > 80])
                    }
                })
        except Exception as e:
            logger.error(f"Failed to calculate blast radius: {e}")
            return web.json_response({"error": str(e)}, status=500)

    async def get_timeline(self, request):
        """Returns static mock timeline data."""
        return web.json_response({
            "snapshots": [
                {
                    "_id": "c2",
                    "timestamp": "2026-03-16T12:00:00Z",
                    "metrics": { "totalAssets": 150, "highRiskAssets": 12 },
                    "driftSummary": { "added": 5, "removed": 2, "modified": 1 }
                },
                {
                    "_id": "c1",
                    "timestamp": "2026-03-15T12:00:00Z",
                    "metrics": { "totalAssets": 147, "highRiskAssets": 10 },
                    "driftSummary": { "added": 0, "removed": 0, "modified": 0 }
                }
            ]
        })

    async def get_timeline_snapshot(self, request):
        """Returns static mock snapshot details."""
        return web.json_response({"snapshot": { "id": request.match_info['snapshot_id'] }})
        
    async def get_events(self, request):
        """Returns static mock event threat intel."""
        return web.json_response([
             {
                "id": "evt-1",
                "type": "DRIFT",
                "severity": "CRITICAL",
                "message": "New public S3 bucket detected matching crown-jewel pattern",
                "timestamp": "2026-03-16T11:45:00Z",
                "metadata": { "assetId": "arn:aws:s3:::customer-pii-exposure" }
             },
             {
                "id": "evt-2",
                "type": "HAPD",
                "severity": "HIGH",
                "message": "Attack path opened from Public Web Server -> Database",
                "timestamp": "2026-03-16T09:30:00Z"
             }
        ])

    async def start(self, host='0.0.0.0', port=4000):
        self._runner = web.AppRunner(self.app)
        await self._runner.setup()  # type: ignore
        self._site = web.TCPSite(self._runner, host, port)
        await self._site.start()  # type: ignore
        logger.info(f"Cloudscape API Native Overlay Server running on http://{host}:{port}")

    async def stop(self):
        if self._driver:
            await self._driver.close()  # type: ignore
        if self._runner:
            await self._runner.cleanup()  # type: ignore
        logger.info("API Overlay Server stopped.")

async def start_api_server():
    server = CloudscapeApiServer()
    await server.start()
    return server
