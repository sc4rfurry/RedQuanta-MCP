#!/usr/bin/env node
/**
 * SVG Asset Generator for RedQuanta MCP
 * Creates custom, complex SVG icons and diagrams
 */

import { writeFileSync, mkdirSync } from 'fs';
import { join } from 'path';

interface SVGAsset {
  name: string;
  category: 'icon' | 'diagram' | 'logo';
  description: string;
  svg: string;
}

const svgAssets: SVGAsset[] = [
  {
    name: 'redquanta-logo',
    category: 'logo',
    description: 'Main RedQuanta MCP logo with security elements',
    svg: `<svg viewBox="0 0 200 80" xmlns="http://www.w3.org/2000/svg">
      <defs>
        <linearGradient id="shieldGradient" x1="0%" y1="0%" x2="100%" y2="100%">
          <stop offset="0%" style="stop-color:#e74c3c;stop-opacity:1" />
          <stop offset="100%" style="stop-color:#c0392b;stop-opacity:1" />
        </linearGradient>
      </defs>
      <path d="M20 25 L20 15 Q20 10 25 10 L35 10 Q40 10 40 15 L40 25 Q40 45 30 50 Q20 45 20 25 Z" 
            fill="url(#shieldGradient)"/>
      <text x="55" y="25" font-family="Arial" font-size="16" font-weight="bold" fill="#2c3e50">RedQuanta</text>
      <text x="55" y="40" font-family="Arial" font-size="10" fill="#7f8c8d">MCP Security Platform</text>
    </svg>`
  },
  {
    name: 'tool-network',
    category: 'icon',
    description: 'Network scanning tool icon',
    svg: `<svg viewBox="0 0 64 64" xmlns="http://www.w3.org/2000/svg">
      <circle cx="32" cy="32" r="28" fill="#27ae60" opacity="0.3"/>
      <circle cx="32" cy="32" r="20" fill="none" stroke="#27ae60" stroke-width="1"/>
      <circle cx="45" cy="20" r="2" fill="#e74c3c"/>
      <circle cx="20" cy="25" r="2" fill="#f39c12"/>
      <circle cx="32" cy="32" r="3" fill="#2c3e50"/>
    </svg>`
  }
];

function generateSVGAssets(): void {
  const assetsDir = join(process.cwd(), 'docs', 'assets');
  mkdirSync(assetsDir, { recursive: true });

  svgAssets.forEach(asset => {
    const filePath = join(assetsDir, `${asset.name}.svg`);
    writeFileSync(filePath, asset.svg);
  });

  console.log('✅ SVG assets generated successfully');
  console.log(`🎨 Generated ${svgAssets.length} SVG assets`);
}

generateSVGAssets();
