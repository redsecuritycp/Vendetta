// PM2 config para vendetta-api (Flask via python directo, port 3004)
const fs = require('fs');
const path = require('path');

function loadEnv(file) {
  const env = {};
  if (!fs.existsSync(file)) return env;
  fs.readFileSync(file, 'utf8').split(/\r?\n/).forEach(line => {
    if (!line || line.startsWith('#')) return;
    const idx = line.indexOf('=');
    if (idx < 0) return;
    const k = line.slice(0, idx).trim();
    let v = line.slice(idx + 1);
    if ((v.startsWith('"') && v.endsWith('"')) || (v.startsWith("'") && v.endsWith("'"))) {
      v = v.slice(1, -1);
    }
    env[k] = v;
  });
  return env;
}

const projectDir = __dirname;
const envVars = loadEnv(path.join(projectDir, '.env'));

module.exports = {
  apps: [{
    name: 'vendetta-api',
    script: 'venv/bin/python',
    args: 'api_server.py',
    cwd: projectDir,
    interpreter: 'none',
    env: { NODE_ENV: 'production', PORT: '3004', PYTHONUNBUFFERED: '1', ...envVars },
    max_memory_restart: '500M',
    autorestart: true,
    watch: false,
    error_file: path.join(projectDir, 'logs/vendetta-api.error.log'),
    out_file: path.join(projectDir, 'logs/vendetta-api.out.log'),
    merge_logs: true,
    time: true,
  }],
};
