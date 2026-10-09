/** @type {import('next').NextConfig} */
const config = {
  experimental: {
    serverComponentsExternalPackages: ['better-sqlite3'],
  },
};

export default config;
