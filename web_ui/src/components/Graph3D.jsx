import { useRef, useMemo, useCallback, useState, useEffect } from 'react';
import { Canvas, useFrame, useThree, invalidate } from '@react-three/fiber';
import { OrbitControls } from '@react-three/drei';
import * as THREE from 'three';
import useStore from '../stores/useStore';

// =============================================================================
// PERFORMANCE-OPTIMIZED GRAPH3D
// Uses InstancedMesh to render thousands of nodes in a single draw call.
// Caps rendered nodes and edges to keep WebGL responsive.
// =============================================================================

const MAX_VISIBLE_NODES = 500;
const MAX_VISIBLE_EDGES = 800;

const DUMMY = new THREE.Object3D();
const COLOR = new THREE.Color();

// Risk/provider → color mapping
function getNodeColor(node) {
  if (node.riskScore > 80) return '#ef4444';
  if (node.riskScore > 50) return '#f97316';
  if (node.provider === 'aws' || node.provider === 'AWS') return '#fbbf24';
  if (node.provider === 'azure' || node.provider === 'AZURE') return '#0ea5e9';
  return '#3b82f6';
}

// ---------------------------------------------------------------------------
// InstancedNodes – one draw call for all spheres
// ---------------------------------------------------------------------------
function InstancedNodes({ nodes, positions, onSelect }) {
  const meshRef = useRef();
  const glowRef = useRef();

  useEffect(() => {
    if (!meshRef.current || !glowRef.current) return;

    nodes.forEach((node, i) => {
      const pos = positions[node.id];
      if (!pos) return;

      DUMMY.position.set(pos[0], pos[1], pos[2]);
      DUMMY.scale.set(1, 1, 1);
      DUMMY.updateMatrix();

      meshRef.current.setMatrixAt(i, DUMMY.matrix);
      glowRef.current.setMatrixAt(i, DUMMY.matrix);

      COLOR.set(getNodeColor(node));
      meshRef.current.setColorAt(i, COLOR);
      glowRef.current.setColorAt(i, COLOR);
    });

    meshRef.current.instanceMatrix.needsUpdate = true;
    glowRef.current.instanceMatrix.needsUpdate = true;
    if (meshRef.current.instanceColor) meshRef.current.instanceColor.needsUpdate = true;
    if (glowRef.current.instanceColor) glowRef.current.instanceColor.needsUpdate = true;

    // Force a re-render so colors appear immediately
    invalidate();
  }, [nodes, positions]);

  const handleClick = useCallback((e) => {
    e.stopPropagation();
    const idx = e.instanceId;
    if (idx !== undefined && nodes[idx]) {
      onSelect(nodes[idx]);
    }
  }, [nodes, onSelect]);

  return (
    <group>
      {/* Main spheres */}
      <instancedMesh
        ref={meshRef}
        args={[undefined, undefined, nodes.length]}
        onClick={handleClick}
      >
        <sphereGeometry args={[0.8, 12, 12]} />
        <meshBasicMaterial
          color="#ffffff"
          transparent
          opacity={0.95}
          toneMapped={false}
        />
      </instancedMesh>

      {/* Glow halos */}
      <instancedMesh
        ref={glowRef}
        args={[undefined, undefined, nodes.length]}
      >
        <sphereGeometry args={[1.1, 8, 8]} />
        <meshBasicMaterial
          color="#ffffff"
          transparent
          opacity={0.3}
          toneMapped={false}
          side={THREE.BackSide}
        />
      </instancedMesh>
    </group>
  );
}

// ---------------------------------------------------------------------------
// BatchEdges – single BufferGeometry for all edge lines
// ---------------------------------------------------------------------------
function BatchEdges({ edges, positions }) {
  const ref = useRef();

  const geometry = useMemo(() => {
    const points = [];
    let count = 0;

    for (const edge of edges) {
      if (count >= MAX_VISIBLE_EDGES) break;
      const src = positions[edge.source];
      const tgt = positions[edge.target];
      if (!src || !tgt) continue;

      points.push(src[0], src[1], src[2]);
      points.push(tgt[0], tgt[1], tgt[2]);
      count++;
    }

    const geo = new THREE.BufferGeometry();
    geo.setAttribute('position', new THREE.Float32BufferAttribute(points, 3));
    return geo;
  }, [edges, positions]);

  return (
    <lineSegments ref={ref} geometry={geometry}>
      <lineBasicMaterial color={0x00a1ff} transparent opacity={0.25} />
    </lineSegments>
  );
}

// ---------------------------------------------------------------------------
// SelectedNodeLabel – only renders a label for the clicked node
// ---------------------------------------------------------------------------
function SelectedNodeLabel({ node, positions }) {
  const pos = positions[node.id];
  if (!pos) return null;

  return (
    <group position={[pos[0], pos[1] + 2.5, pos[2]]}>
      <sprite scale={[6, 1.5, 1]}>
        <spriteMaterial
          color="#ffffff"
          transparent
          opacity={0.85}
          sizeAttenuation={false}
        />
      </sprite>
    </group>
  );
}

// ---------------------------------------------------------------------------
// ClickHandler – manual raycasting that works WITH OrbitControls
// Detects short clicks (not drags) and finds the nearest node sphere
// ---------------------------------------------------------------------------
function ClickHandler({ nodes, positions, onSelect }) {
  const { camera, gl, raycaster, pointer } = useThree();
  const downPos = useRef({ x: 0, y: 0 });

  useEffect(() => {
    const canvas = gl.domElement;

    const onPointerDown = (e) => {
      downPos.current = { x: e.clientX, y: e.clientY };
    };

    const onPointerUp = (e) => {
      // Only trigger if the mouse didn't drag (click, not orbit)
      const dx = e.clientX - downPos.current.x;
      const dy = e.clientY - downPos.current.y;
      const dist = Math.sqrt(dx * dx + dy * dy);
      if (dist > 5) return; // was a drag, not a click

      // Convert mouse position to NDC
      const rect = canvas.getBoundingClientRect();
      const ndcX = ((e.clientX - rect.left) / rect.width) * 2 - 1;
      const ndcY = -((e.clientY - rect.top) / rect.height) * 2 + 1;

      // Create a ray from the camera
      raycaster.setFromCamera({ x: ndcX, y: ndcY }, camera);
      const ray = raycaster.ray;

      // Find the closest node to the ray
      let closestNode = null;
      let closestDist = Infinity;
      const hitRadius = 1.2; // slightly bigger than sphere radius for easier clicking

      for (const node of nodes) {
        const pos = positions[node.id];
        if (!pos) continue;

        const nodePos = new THREE.Vector3(pos[0], pos[1], pos[2]);
        const distToRay = ray.distanceToPoint(nodePos);

        if (distToRay < hitRadius && distToRay < closestDist) {
          closestDist = distToRay;
          closestNode = node;
        }
      }

      if (closestNode) {
        onSelect(closestNode);
      }
    };

    canvas.addEventListener('pointerdown', onPointerDown);
    canvas.addEventListener('pointerup', onPointerUp);

    return () => {
      canvas.removeEventListener('pointerdown', onPointerDown);
      canvas.removeEventListener('pointerup', onPointerUp);
    };
  }, [camera, gl, raycaster, nodes, positions, onSelect]);

  return null; // This component only handles events, renders nothing
}

// ---------------------------------------------------------------------------
// Scene
// ---------------------------------------------------------------------------
function Scene({ nodes, edges }) {
  const { setSelectedNode } = useStore();

  // Sample down if too many nodes – pick top risk + random sample
  const visibleNodes = useMemo(() => {
    if (nodes.length <= MAX_VISIBLE_NODES) return nodes;

    // Always include high-risk nodes first
    const highRisk = nodes.filter(n => n.riskScore > 50);
    const rest = nodes.filter(n => n.riskScore <= 50);

    // Shuffle rest and take enough to fill the cap
    const shuffled = rest.sort(() => Math.random() - 0.5);
    const remaining = MAX_VISIBLE_NODES - highRisk.length;
    return [...highRisk.slice(0, MAX_VISIBLE_NODES), ...shuffled.slice(0, Math.max(0, remaining))].slice(0, MAX_VISIBLE_NODES);
  }, [nodes]);

  // Build a set of visible node IDs for edge filtering
  const visibleIdSet = useMemo(() => new Set(visibleNodes.map(n => n.id)), [visibleNodes]);

  const visibleEdges = useMemo(() => {
    return edges.filter(e => visibleIdSet.has(e.source) && visibleIdSet.has(e.target));
  }, [edges, visibleIdSet]);

  // Precalculate positions – fibonacci sphere distribution
  const positions = useMemo(() => {
    const pos = {};
    const count = visibleNodes.length;
    const radius = Math.max(15, Math.sqrt(count) * 1.5);

    visibleNodes.forEach((node, i) => {
      const phi = Math.acos(-1 + (2 * i) / count);
      const theta = Math.sqrt(count * Math.PI) * phi;

      pos[node.id] = [
        radius * Math.cos(theta) * Math.sin(phi),
        radius * Math.sin(theta) * Math.sin(phi),
        radius * Math.cos(phi)
      ];
    });
    return pos;
  }, [visibleNodes]);

  return (
    <>
      <ambientLight intensity={0.4} />
      <pointLight position={[30, 30, 30]} intensity={1.5} color="#ffffff" />
      <pointLight position={[-30, -30, -30]} intensity={0.8} color="#00a1ff" />

      <BatchEdges edges={visibleEdges} positions={positions} />
      <InstancedNodes nodes={visibleNodes} positions={positions} onSelect={setSelectedNode} />
      <ClickHandler nodes={visibleNodes} positions={positions} onSelect={setSelectedNode} />

      <OrbitControls
        enableDamping
        dampingFactor={0.05}
        minDistance={5}
        maxDistance={150}
      />
    </>
  );
}

// ---------------------------------------------------------------------------
// Graph3D (exported)
// ---------------------------------------------------------------------------
export default function Graph3D({ nodes, edges }) {
  const [ready, setReady] = useState(false);

  useEffect(() => {
    // Defer heavy render to next frame to avoid blocking navigation
    const id = requestAnimationFrame(() => setReady(true));
    return () => cancelAnimationFrame(id);
  }, []);

  if (!nodes || nodes.length === 0) {
    return (
      <div style={{ color: '#8899aa', padding: 40, textAlign: 'center', fontSize: 14 }}>
        Loading topology data from API...
      </div>
    );
  }

  if (!ready) {
    return (
      <div style={{ color: '#8899aa', padding: 40, textAlign: 'center', fontSize: 14 }}>
        Initializing 3D renderer for {nodes.length.toLocaleString()} nodes...
      </div>
    );
  }

  return (
    <Canvas
      camera={{ position: [0, 0, 40], fov: 60 }}
      gl={{ antialias: false, powerPreference: 'high-performance', toneMapping: THREE.NoToneMapping }}
      dpr={[1, 1.5]}
      frameloop="always"
    >
      <color attach="background" args={['#0a111a']} />
      <Scene nodes={nodes} edges={edges} />
    </Canvas>
  );
}
