import { createMDX } from 'fumadocs-mdx/next';

const withMDX = createMDX();

/** @type {import('next').NextConfig} */
const config = {
  // Fully static output, served by Cloudflare Workers static assets (see wrangler.jsonc).
  output: 'export',
  reactStrictMode: true,
  images: { unoptimized: true },
};

export default withMDX(config);
