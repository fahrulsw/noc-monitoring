// ecosystem.config.js
module.exports = {
  apps: [{
    name: 'onu-activator',              // sesuaikan dengan nama process kamu di pm2 list
    script: 'server.js',
    env: {
      FFMPEG_AGENT_URL: 'http://192.168.11.26:4002',
      FFMPEG_AGENT_KEY: 'e6d8325faabc1693390628ea61619ab544749bea543b136290818055ce01ce44',
      // kalau ada env lain yang sudah kamu pakai (JWT_SECRET, dll), taruh di sini juga
    }
  }]
};