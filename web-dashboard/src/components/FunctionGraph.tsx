import React, { useEffect, useRef } from 'react';
import cytoscape from 'cytoscape';

interface FunctionNode {
  id: string;
  name: string;
  address: string;
  size: number;
  complexity: number;
}

interface FunctionEdge {
  source: string;
  target: string;
  type: 'call' | 'jump' | 'return';
}

interface FunctionGraphProps {
  functions: FunctionNode[];
  edges: FunctionEdge[];
  onNodeClick?: (node: FunctionNode) => void;
}

const FunctionGraph: React.FC<FunctionGraphProps> = ({
  functions,
  edges,
  onNodeClick
}) => {
  const containerRef = useRef<HTMLDivElement>(null);
  const cyRef = useRef<cytoscape.Core | null>(null);

  useEffect(() => {
    if (!containerRef.current) return;

    // Convert functions to Cytoscape elements
    const nodes = functions.map(func => ({
      data: {
        id: func.id,
        label: func.name,
        address: func.address,
        size: func.size,
        complexity: func.complexity,
        type: 'function'
      },
      classes: 'function-node'
    }));

    const cyEdges = edges.map(edge => ({
      data: {
        id: `${edge.source}-${edge.target}`,
        source: edge.source,
        target: edge.target,
        type: edge.type
      },
      classes: `edge-${edge.type}`
    }));

    // Initialize Cytoscape
    cyRef.current = cytoscape({
      container: containerRef.current,
      elements: [...nodes, ...cyEdges],
      style: [
        {
          selector: 'node',
          style: {
            'background-color': '#4A90E2',
            'label': 'data(label)',
            'font-size': '12px',
            'text-valign': 'center',
            'text-halign': 'center',
            'color': '#fff',
            'width': 'data(size)',
            'height': 'data(size)',
            'min-width': '40px',
            'min-height': '40px'
          }
        },
        {
          selector: 'node.function-node',
          style: {
            'background-color': '#4A90E2',
            'border-color': '#357ABD',
            'border-width': '2px'
          }
        },
        {
          selector: 'edge',
          style: {
            'width': '2px',
            'line-color': '#999',
            'target-arrow-color': '#999',
            'target-arrow-shape': 'triangle',
            'curve-style': 'bezier'
          }
        },
        {
          selector: 'edge.edge-call',
          style: {
            'line-color': '#28a745',
            'target-arrow-color': '#28a745'
          }
        },
        {
          selector: 'edge.edge-jump',
          style: {
            'line-color': '#ffc107',
            'target-arrow-color': '#ffc107'
          }
        },
        {
          selector: 'edge.edge-return',
          style: {
            'line-color': '#dc3545',
            'target-arrow-color': '#dc3545'
          }
        },
        {
          selector: 'node:selected',
          style: {
            'background-color': '#FF6B6B',
            'border-color': '#FF5252',
            'border-width': '3px'
          }
        }
      ],
      layout: {
        name: 'cose',
        animate: true,
        animationDuration: 1000,
        fit: true,
        padding: 30
      }
    });

    // Add event listeners
    cyRef.current.on('tap', 'node', (event) => {
      const node = event.target;
      const nodeData = node.data();
      if (onNodeClick) {
        const func = functions.find(f => f.id === nodeData.id);
        if (func) onNodeClick(func);
      }
    });

    // Cleanup
    return () => {
      if (cyRef.current) {
        cyRef.current.destroy();
      }
    };
  }, [functions, edges, onNodeClick]);

  // Update layout when data changes
  useEffect(() => {
    if (cyRef.current) {
      cyRef.current.layout({
        name: 'cose',
        animate: true,
        animationDuration: 500,
        fit: true,
        padding: 30
      }).run();
    }
  }, [functions, edges]);

  return (
    <div className="function-graph-container">
      <div
        ref={containerRef}
        className="function-graph"
        style={{ width: '100%', height: '600px' }}
      />
      <div className="graph-legend">
        <div className="legend-item">
          <div className="legend-color" style={{ backgroundColor: '#4A90E2' }}></div>
          <span>Function</span>
        </div>
        <div className="legend-item">
          <div className="legend-color" style={{ backgroundColor: '#28a745' }}></div>
          <span>Call</span>
        </div>
        <div className="legend-item">
          <div className="legend-color" style={{ backgroundColor: '#ffc107' }}></div>
          <span>Jump</span>
        </div>
        <div className="legend-item">
          <div className="legend-color" style={{ backgroundColor: '#dc3545' }}></div>
          <span>Return</span>
        </div>
      </div>
    </div>
  );
};

export default FunctionGraph;
