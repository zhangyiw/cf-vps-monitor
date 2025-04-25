// 合并前后端的单一Worker解决方案

// 处理请求的主函数
export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    const path = url.pathname;
    
    // 处理API请求
    if (path.startsWith('/api/')) {
      return handleApiRequest(request, env);
    }
    
    // 处理安装脚本
    if (path === '/install.sh') {
      return handleInstallScript(request, url);
    }
    
    // 处理前端静态文件
    return handleFrontendRequest(request, path);
  }
};

// 处理API请求
async function handleApiRequest(request, env) {
  const url = new URL(request.url);
  const path = url.pathname;
  const method = request.method;
  
  // CORS处理
  const corsHeaders = {
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type, Authorization, X-API-Key',
  };
  
  // 处理OPTIONS请求
  if (method === 'OPTIONS') {
    return new Response(null, {
      status: 204,
      headers: corsHeaders
    });
  }
  
  // 处理登录请求
  if (path === '/api/auth/login' && method === 'POST') {
    try {
      const { username, password } = await request.json();
      
      // 从KV获取管理员凭证
      let adminCredentials = await env.AUTH_STORE.get('admin_credentials', { type: 'json' });
      
      // 如果没有管理员凭证，使用默认凭证
      if (!adminCredentials) {
        // 默认凭证: admin/admin
        adminCredentials = {
          username: 'admin',
          password: 'admin'  // 简化版本，不使用哈希
        };
        
        // 保存默认凭证到KV
        await env.AUTH_STORE.put('admin_credentials', JSON.stringify(adminCredentials));
      }
      
      // 验证用户名和密码
      if (username === adminCredentials.username && password === adminCredentials.password) {
        // 生成简单token
        const token = btoa(username + ':' + Date.now());
        
        return new Response(JSON.stringify({ token }), {
          headers: { 'Content-Type': 'application/json', ...corsHeaders }
        });
      }
      
      // 验证失败
      return new Response(JSON.stringify({ error: 'Invalid credentials', message: '用户名或密码错误' }), {
        status: 401,
        headers: { 'Content-Type': 'application/json', ...corsHeaders }
      });
    } catch (error) {
      return new Response(JSON.stringify({ error: error.message }), {
        status: 500,
        headers: { 'Content-Type': 'application/json', ...corsHeaders }
      });
    }
  }
  
  // 处理登录状态检查
  if (path === '/api/auth/status' && method === 'GET') {
    const authHeader = request.headers.get('Authorization');
    const authenticated = authHeader && authHeader.startsWith('Bearer ');
    
    return new Response(JSON.stringify({ authenticated }), {
      headers: { 'Content-Type': 'application/json', ...corsHeaders }
    });
  }
  
  // 处理获取服务器列表
  if (path === '/api/servers' && method === 'GET') {
    try {
      // 从KV获取服务器列表
      const serversList = await env.SERVERS_STORE.get('servers_list', { type: 'json' }) || { servers: [] };
      
      return new Response(JSON.stringify(serversList), {
        headers: { 'Content-Type': 'application/json', ...corsHeaders }
      });
    } catch (error) {
      return new Response(JSON.stringify({ error: error.message }), {
        status: 500,
        headers: { 'Content-Type': 'application/json', ...corsHeaders }
      });
    }
  }
  
  // 处理获取服务器状态
  if (path.startsWith('/api/status/') && method === 'GET') {
    try {
      const serverId = path.split('/').pop();
      
      // 从KV获取服务器信息
      const serverKey = `server:${serverId}`;
      const serverData = await env.SERVERS_STORE.get(serverKey, { type: 'json' });
      
      if (!serverData) {
        return new Response(JSON.stringify({ error: 'Server not found' }), {
          status: 404,
          headers: { 'Content-Type': 'application/json', ...corsHeaders }
        });
      }
      
      // 从KV获取最新监控数据
      const metricsKey = `metrics:${serverId}:latest`;
      const metricsData = await env.METRICS_STORE.get(metricsKey, { type: 'json' });
      
      // 准备响应数据
      const responseData = {
        server: {
          id: serverData.id,
          name: serverData.name,
          description: serverData.description
        },
        metrics: metricsData || null
      };
      
      return new Response(JSON.stringify(responseData), {
        headers: { 'Content-Type': 'application/json', ...corsHeaders }
      });
    } catch (error) {
      return new Response(JSON.stringify({ error: error.message }), {
        status: 500,
        headers: { 'Content-Type': 'application/json', ...corsHeaders }
      });
    }
  }
  
  // 处理管理API - 获取所有服务器
  if (path === '/api/admin/servers' && method === 'GET') {
    try {
      // 从KV获取服务器列表
      const serversList = await env.SERVERS_STORE.get('servers_list', { type: 'json' }) || { servers: [] };
      
      // 获取每个服务器的详细信息
      const serversWithDetails = await Promise.all(serversList.servers.map(async server => {
        const serverKey = `server:${server.id}`;
        const serverData = await env.SERVERS_STORE.get(serverKey, { type: 'json' });
        
        // 获取最新监控数据的时间戳
        const metricsKey = `metrics:${server.id}:latest`;
        const metricsData = await env.METRICS_STORE.get(metricsKey, { type: 'json' });
        
        return {
          ...serverData,
          api_key: undefined, // 不返回API密钥
          last_report: metricsData ? metricsData.timestamp : null
        };
      }));
      
      return new Response(JSON.stringify({ servers: serversWithDetails }), {
        headers: { 'Content-Type': 'application/json', ...corsHeaders }
      });
    } catch (error) {
      return new Response(JSON.stringify({ error: error.message }), {
        status: 500,
        headers: { 'Content-Type': 'application/json', ...corsHeaders }
      });
    }
  }
  
  // 处理管理API - 添加新服务器
  if (path === '/api/admin/servers' && method === 'POST') {
    try {
      const { name, description } = await request.json();
      
      // 验证输入
      if (!name) {
        return new Response(JSON.stringify({ error: 'Server name is required' }), {
          status: 400,
          headers: { 'Content-Type': 'application/json', ...corsHeaders }
        });
      }
      
      // 生成服务器ID和API密钥
      const serverId = Math.random().toString(36).substring(2, 10);
      const apiKey = Math.random().toString(36).substring(2, 15) + 
                     Math.random().toString(36).substring(2, 15);
      
      // 创建服务器对象
      const serverData = {
        id: serverId,
        name,
        description: description || '',
        api_key: apiKey,
        created_at: Math.floor(Date.now() / 1000)
      };
      
      // 保存服务器数据到KV
      const serverKey = `server:${serverId}`;
      await env.SERVERS_STORE.put(serverKey, JSON.stringify(serverData));
      
      // 更新服务器列表
      const serversList = await env.SERVERS_STORE.get('servers_list', { type: 'json' }) || { servers: [] };
      serversList.servers.push({
        id: serverId,
        name,
        description: description || ''
      });
      await env.SERVERS_STORE.put('servers_list', JSON.stringify(serversList));
      
      // 返回服务器数据（包含API密钥）
      return new Response(JSON.stringify({ server: serverData }), {
        headers: { 'Content-Type': 'application/json', ...corsHeaders }
      });
    } catch (error) {
      return new Response(JSON.stringify({ error: error.message }), {
        status: 500,
        headers: { 'Content-Type': 'application/json', ...corsHeaders }
      });
    }
  }
  
  // 处理管理API - 删除服务器
  if (path.match(/\/api\/admin\/servers\/[^\/]+$/) && method === 'DELETE') {
    try {
      const serverId = path.split('/').pop();
      
      // 从KV获取服务器列表
      const serversList = await env.SERVERS_STORE.get('servers_list', { type: 'json' }) || { servers: [] };
      
      // 检查服务器是否存在
      const serverIndex = serversList.servers.findIndex(s => s.id === serverId);
      if (serverIndex === -1) {
        return new Response(JSON.stringify({ error: 'Server not found' }), {
          status: 404,
          headers: { 'Content-Type': 'application/json', ...corsHeaders }
        });
      }
      
      // 从列表中删除服务器
      serversList.servers.splice(serverIndex, 1);
      await env.SERVERS_STORE.put('servers_list', JSON.stringify(serversList));
      
      // 删除服务器数据
      const serverKey = `server:${serverId}`;
      await env.SERVERS_STORE.delete(serverKey);
      
      // 删除监控数据
      const metricsKey = `metrics:${serverId}:latest`;
      await env.METRICS_STORE.delete(metricsKey);
      
      return new Response(JSON.stringify({ success: true }), {
        headers: { 'Content-Type': 'application/json', ...corsHeaders }
      });
    } catch (error) {
      return new Response(JSON.stringify({ error: error.message }), {
        status: 500,
        headers: { 'Content-Type': 'application/json', ...corsHeaders }
      });
    }
  }
  
  // 处理管理API - 更新服务器
  if (path.match(/\/api\/admin\/servers\/[^\/]+$/) && method === 'PUT') {
    try {
      const serverId = path.split('/').pop();
      const { name, description } = await request.json();
      
      // 验证输入
      if (!name) {
        return new Response(JSON.stringify({ error: 'Server name is required' }), {
          status: 400,
          headers: { 'Content-Type': 'application/json', ...corsHeaders }
        });
      }
      
      // 从KV获取服务器数据
      const serverKey = `server:${serverId}`;
      const serverData = await env.SERVERS_STORE.get(serverKey, { type: 'json' });
      
      if (!serverData) {
        return new Response(JSON.stringify({ error: 'Server not found' }), {
          status: 404,
          headers: { 'Content-Type': 'application/json', ...corsHeaders }
        });
      }
      
      // 更新服务器数据
      serverData.name = name;
      serverData.description = description || '';
      await env.SERVERS_STORE.put(serverKey, JSON.stringify(serverData));
      
      // 更新服务器列表
      const serversList = await env.SERVERS_STORE.get('servers_list', { type: 'json' }) || { servers: [] };
      const serverIndex = serversList.servers.findIndex(s => s.id === serverId);
      if (serverIndex !== -1) {
        serversList.servers[serverIndex].name = name;
        serversList.servers[serverIndex].description = description || '';
        await env.SERVERS_STORE.put('servers_list', JSON.stringify(serversList));
      }
      
      return new Response(JSON.stringify({ success: true }), {
        headers: { 'Content-Type': 'application/json', ...corsHeaders }
      });
    } catch (error) {
      return new Response(JSON.stringify({ error: error.message }), {
        status: 500,
        headers: { 'Content-Type': 'application/json', ...corsHeaders }
      });
    }
  }
  
  // 处理数据上报API
  if (path.startsWith('/api/report/') && method === 'POST') {
    try {
      const serverId = path.split('/').pop();
      const apiKey = request.headers.get('X-API-Key');
      
      if (!apiKey) {
        return new Response(JSON.stringify({ error: 'API key required' }), {
          status: 401,
          headers: { 'Content-Type': 'application/json', ...corsHeaders }
        });
      }
      
      // 从KV获取服务器数据
      const serverKey = `server:${serverId}`;
      const serverData = await env.SERVERS_STORE.get(serverKey, { type: 'json' });
      
      if (!serverData) {
        return new Response(JSON.stringify({ error: 'Server not found' }), {
          status: 404,
          headers: { 'Content-Type': 'application/json', ...corsHeaders }
        });
      }
      
      if (serverData.api_key !== apiKey) {
        return new Response(JSON.stringify({ error: 'Invalid API key' }), {
          status: 401,
          headers: { 'Content-Type': 'application/json', ...corsHeaders }
        });
      }
      
      // 解析上报的数据
      const reportData = await request.json();
      
      // 验证数据格式
      if (!reportData.timestamp || !reportData.cpu || !reportData.memory || !reportData.disk || !reportData.network) {
        return new Response(JSON.stringify({ error: 'Invalid data format' }), {
          status: 400,
          headers: { 'Content-Type': 'application/json', ...corsHeaders }
        });
      }
      
      // 保存监控数据到KV
      const metricsKey = `metrics:${serverId}:latest`;
      await env.METRICS_STORE.put(metricsKey, JSON.stringify(reportData));
      
      return new Response(JSON.stringify({ success: true }), {
        headers: { 'Content-Type': 'application/json', ...corsHeaders }
      });
    } catch (error) {
      return new Response(JSON.stringify({ error: error.message }), {
        status: 500,
        headers: { 'Content-Type': 'application/json', ...corsHeaders }
      });
    }
  }
  
  // 处理管理API - 获取服务器的API密钥
  if (path.match(/\/api\/admin\/servers\/[^\/]+\/key/) && method === 'GET') {
    try {
      const serverId = path.split('/')[4];
      
      // 从KV获取服务器数据
      const serverKey = `server:${serverId}`;
      const serverData = await env.SERVERS_STORE.get(serverKey, { type: 'json' });
      
      if (!serverData) {
        return new Response(JSON.stringify({ error: 'Server not found' }), {
          status: 404,
          headers: { 'Content-Type': 'application/json', ...corsHeaders }
        });
      }
      
      return new Response(JSON.stringify({ api_key: serverData.api_key }), {
        headers: { 'Content-Type': 'application/json', ...corsHeaders }
      });
    } catch (error) {
      return new Response(JSON.stringify({ error: error.message }), {
        status: 500,
        headers: { 'Content-Type': 'application/json', ...corsHeaders }
      });
    }
  }
  
  // 处理密码修改API
  if (path === '/api/auth/change-password' && method === 'POST') {
    try {
      const { current_password, new_password } = await request.json();
      
      // 验证输入
      if (!current_password || !new_password) {
        return new Response(JSON.stringify({ error: 'Current password and new password are required' }), {
          status: 400,
          headers: { 'Content-Type': 'application/json', ...corsHeaders }
        });
      }
      
      // 从KV获取管理员凭证
      let adminCredentials = await env.AUTH_STORE.get('admin_credentials', { type: 'json' });
      
      // 如果没有管理员凭证，使用默认凭证
      if (!adminCredentials) {
        adminCredentials = {
          username: 'admin',
          password: 'admin'
        };
      }
      
      // 验证当前密码
      if (adminCredentials.password !== current_password) {
        return new Response(JSON.stringify({ error: 'Current password is incorrect', message: '当前密码不正确' }), {
          status: 400,
          headers: { 'Content-Type': 'application/json', ...corsHeaders }
        });
      }
      
      // 更新密码
      adminCredentials.password = new_password;
      await env.AUTH_STORE.put('admin_credentials', JSON.stringify(adminCredentials));
      
      return new Response(JSON.stringify({ success: true }), {
        headers: { 'Content-Type': 'application/json', ...corsHeaders }
      });
    } catch (error) {
      return new Response(JSON.stringify({ error: error.message }), {
        status: 500,
        headers: { 'Content-Type': 'application/json', ...corsHeaders }
      });
    }
  }
  
  // 未找到匹配的路由
  return new Response(JSON.stringify({ error: 'Not found' }), {
    status: 404,
    headers: { 'Content-Type': 'application/json', ...corsHeaders }
  });
}

// 处理安装脚本
function handleInstallScript(request, url) {
  const baseUrl = url.origin;
  
  const script = `#!/bin/bash
# VPS监控脚本 - 安装程序

# 默认值
API_KEY=""
SERVER_ID=""
WORKER_URL="${baseUrl}"
INSTALL_DIR="/opt/vps-monitor"
SERVICE_NAME="vps-monitor"

# 解析参数
while [[ $# -gt 0 ]]; do
  case $1 in
    -k|--key)
      API_KEY="$2"
      shift 2
      ;;
    -s|--server)
      SERVER_ID="$2"
      shift 2
      ;;
    -u|--url)
      WORKER_URL="$2"
      shift 2
      ;;
    -d|--dir)
      INSTALL_DIR="$2"
      shift 2
      ;;
    *)
      echo "未知参数: $1"
      exit 1
      ;;
  esac
done

# 检查必要参数
if [ -z "$API_KEY" ] || [ -z "$SERVER_ID" ]; then
  echo "错误: API密钥和服务器ID是必需的"
  echo "用法: $0 -k API_KEY -s SERVER_ID [-u WORKER_URL] [-d INSTALL_DIR]"
  exit 1
fi

# 检查权限
if [ "$(id -u)" -ne 0 ]; then
  echo "错误: 此脚本需要root权限"
  exit 1
fi

echo "=== VPS监控脚本安装程序 ==="
echo "安装目录: $INSTALL_DIR"
echo "Worker URL: $WORKER_URL"

# 创建安装目录
mkdir -p "$INSTALL_DIR"
cd "$INSTALL_DIR" || exit 1

# 创建监控脚本
cat > "$INSTALL_DIR/monitor.sh" << 'EOF'
#!/bin/bash

# 配置
API_KEY="__API_KEY__"
SERVER_ID="__SERVER_ID__"
WORKER_URL="__WORKER_URL__"
INTERVAL=60  # 上报间隔（秒）

# 日志函数
log() {
  echo "$(date '+%Y-%m-%d %H:%M:%S') - $1"
}

# 获取CPU使用率
get_cpu_usage() {
  cpu_usage=$(top -bn1 | grep "Cpu(s)" | sed "s/.*, *\\([0-9.]*\\)%* id.*/\\1/" | awk '{print 100 - $1}')
  cpu_load=$(cat /proc/loadavg | awk '{print $1","$2","$3}')
  echo "{\"usage_percent\":$cpu_usage,\"load_avg\":[$cpu_load]}"
}

# 获取内存使用情况
get_memory_usage() {
  total=$(free -k | grep Mem | awk '{print $2}')
  used=$(free -k | grep Mem | awk '{print $3}')
  free=$(free -k | grep Mem | awk '{print $4}')
  usage_percent=$(echo "scale=1; $used * 100 / $total" | bc)
  echo "{\"total\":$total,\"used\":$used,\"free\":$free,\"usage_percent\":$usage_percent}"
}

# 获取硬盘使用情况
get_disk_usage() {
  disk_info=$(df -k / | tail -1)
  total=$(echo "$disk_info" | awk '{print $2 / 1024 / 1024}')
  used=$(echo "$disk_info" | awk '{print $3 / 1024 / 1024}')
  free=$(echo "$disk_info" | awk '{print $4 / 1024 / 1024}')
  usage_percent=$(echo "$disk_info" | awk '{print $5}' | tr -d '%')
  echo "{\"total\":$total,\"used\":$used,\"free\":$free,\"usage_percent\":$usage_percent}"
}

# 获取网络使用情况
get_network_usage() {
  # 检查是否安装了ifstat
  if ! command -v ifstat &> /dev/null; then
    log "ifstat未安装，无法获取网络速度"
    echo "{\"upload_speed\":0,\"download_speed\":0,\"total_upload\":0,\"total_download\":0}"
    return
  fi
  
  # 获取网络接口
  interface=$(ip route | grep default | awk '{print $5}')
  
  # 获取网络速度（KB/s）
  network_speed=$(ifstat -i "$interface" 1 1 | tail -1)
  download_speed=$(echo "$network_speed" | awk '{print $1 * 1024}')
  upload_speed=$(echo "$network_speed" | awk '{print $2 * 1024}')
  
  # 获取总流量
  rx_bytes=$(cat /proc/net/dev | grep "$interface" | awk '{print $2}')
  tx_bytes=$(cat /proc/net/dev | grep "$interface" | awk '{print $10}')
  
  echo "{\"upload_speed\":$upload_speed,\"download_speed\":$download_speed,\"total_upload\":$tx_bytes,\"total_download\":$rx_bytes}"
}

# 上报数据
report_metrics() {
  timestamp=$(date +%s)
  cpu=$(get_cpu_usage)
  memory=$(get_memory_usage)
  disk=$(get_disk_usage)
  network=$(get_network_usage)
  
  data="{\"timestamp\":$timestamp,\"cpu\":$cpu,\"memory\":$memory,\"disk\":$disk,\"network\":$network}"
  
  log "正在上报数据..."
  log "API密钥: $API_KEY"
  log "服务器ID: $SERVER_ID"
  log "Worker URL: $WORKER_URL"
  
  response=$(curl -s -X POST "$WORKER_URL/api/report/$SERVER_ID" \
    -H "Content-Type: application/json" \
    -H "X-API-Key: $API_KEY" \
    -d "$data")
  
  if [[ "$response" == *"success"* ]]; then
    log "数据上报成功"
  else
    log "数据上报失败: $response"
  fi
}

# 安装依赖
install_dependencies() {
  log "检查并安装依赖..."
  
  # 检测包管理器
  if command -v apt-get &> /dev/null; then
    PKG_MANAGER="apt-get"
  elif command -v yum &> /dev/null; then
    PKG_MANAGER="yum"
  else
    log "不支持的系统，无法自动安装依赖"
    return 1
  fi
  
  # 安装依赖
  $PKG_MANAGER update -y
  $PKG_MANAGER install -y bc curl ifstat
  
  log "依赖安装完成"
  return 0
}

# 主函数
main() {
  log "VPS监控脚本启动"
  
  # 安装依赖
  install_dependencies
  
  # 主循环
  while true; do
    report_metrics
    sleep $INTERVAL
  done
}

# 启动主函数
main
EOF

# 替换配置
sed -i "s|__API_KEY__|$API_KEY|g" "$INSTALL_DIR/monitor.sh"
sed -i "s|__SERVER_ID__|$SERVER_ID|g" "$INSTALL_DIR/monitor.sh"
sed -i "s|__WORKER_URL__|$WORKER_URL|g" "$INSTALL_DIR/monitor.sh"

# 设置执行权限
chmod +x "$INSTALL_DIR/monitor.sh"

# 创建systemd服务
cat > "/etc/systemd/system/$SERVICE_NAME.service" << EOF
[Unit]
Description=VPS Monitor Service
After=network.target

[Service]
ExecStart=$INSTALL_DIR/monitor.sh
Restart=always
User=root
Group=root
Environment=PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

[Install]
WantedBy=multi-user.target
EOF

# 启动服务
systemctl daemon-reload
systemctl enable "$SERVICE_NAME"
systemctl start "$SERVICE_NAME"

echo "=== 安装完成 ==="
echo "服务已启动并设置为开机自启"
echo "查看服务状态: systemctl status $SERVICE_NAME"
echo "查看服务日志: journalctl -u $SERVICE_NAME -f"
`;

  return new Response(script, {
    headers: {
      'Content-Type': 'text/plain',
      'Content-Disposition': 'attachment; filename="install.sh"'
    }
  });
}

// 处理前端请求
function handleFrontendRequest(request, path) {
  // 默认页面
  if (path === '/' || path === '') {
    return new Response(getIndexHtml(), {
      headers: { 'Content-Type': 'text/html' }
    });
  }
  
  // 登录页面
  if (path === '/login' || path === '/login.html') {
    return new Response(getLoginHtml(), {
      headers: { 'Content-Type': 'text/html' }
    });
  }
  
  // 管理页面
  if (path === '/admin' || path === '/admin.html') {
    return new Response(getAdminHtml(), {
      headers: { 'Content-Type': 'text/html' }
    });
  }
  
  // CSS文件
  if (path === '/css/style.css') {
    return new Response(getStyleCss(), {
      headers: { 'Content-Type': 'text/css' }
    });
  }
  
  // JavaScript文件
  if (path === '/js/main.js') {
    return new Response(getMainJs(), {
      headers: { 'Content-Type': 'application/javascript' }
    });
  }
  
  if (path === '/js/login.js') {
    return new Response(getLoginJs(), {
      headers: { 'Content-Type': 'application/javascript' }
    });
  }
  
  if (path === '/js/admin.js') {
    return new Response(getAdminJs(), {
      headers: { 'Content-Type': 'application/javascript' }
    });
  }
  
  // 404页面
  return new Response('Not Found', {
    status: 404,
    headers: { 'Content-Type': 'text/plain' }
  });
}

// 前端HTML、CSS和JavaScript文件内容
function getIndexHtml() {
  return `<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>VPS监控面板</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css" rel="stylesheet">
    <link href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.8.1/font/bootstrap-icons.css" rel="stylesheet">
    <link href="/css/style.css" rel="stylesheet">
    <script src="https://cdn.jsdelivr.net/npm/chart.js@3.7.1/dist/chart.min.js"></script>
</head>
<body>
    <nav class="navbar navbar-expand-lg navbar-dark bg-primary">
        <div class="container">
            <a class="navbar-brand" href="/">VPS监控面板</a>
            <button class="navbar-toggler" type="button" data-bs-toggle="collapse" data-bs-target="#navbarNav">
                <span class="navbar-toggler-icon"></span>
            </button>
            <div class="collapse navbar-collapse" id="navbarNav">
                <ul class="navbar-nav me-auto">
                    <li class="nav-item dropdown">
                        <a class="nav-link dropdown-toggle" href="#" id="serverSelector" role="button" data-bs-toggle="dropdown">
                            选择服务器
                        </a>
                        <ul class="dropdown-menu" id="serverList">
                            <li><a class="dropdown-item" href="#">加载中...</a></li>
                        </ul>
                    </li>
                </ul>
                <ul class="navbar-nav">
                    <li class="nav-item">
                        <a class="nav-link" href="/login.html">管理员登录</a>
                    </li>
                </ul>
            </div>
        </div>
    </nav>

    <div class="container mt-4">
        <div id="noServers" class="alert alert-info">
            暂无服务器数据，请先登录管理后台添加服务器。
        </div>

        <div id="serverData" class="d-none">
            <div class="row mb-4">
                <div class="col-md-6">
                    <div class="card">
                        <div class="card-header">
                            <h5 class="card-title mb-0">服务器信息</h5>
                        </div>
                        <div class="card-body">
                            <div class="d-flex justify-content-between mb-3">
                                <div>
                                    <h4 id="serverName">服务器名称</h4>
                                    <p id="serverDescription" class="text-muted">服务器描述</p>
                                </div>
                                <div>
                                    <span id="serverStatus" class="badge bg-secondary">未知</span>
                                </div>
                            </div>
                            <p class="mb-0">最后更新: <span id="lastUpdate">-</span></p>
                        </div>
                    </div>
                </div>
                <div class="col-md-6">
                    <div class="card">
                        <div class="card-header">
                            <h5 class="card-title mb-0">网络状态</h5>
                        </div>
                        <div class="card-body">
                            <div class="row">
                                <div class="col-6">
                                    <div class="mb-3">
                                        <label class="form-label">上传速度</label>
                                        <h4 id="uploadSpeed">0 B/s</h4>
                                    </div>
                                    <div>
                                        <label class="form-label">总上传流量</label>
                                        <h4 id="totalUpload">0 B</h4>
                                    </div>
                                </div>
                                <div class="col-6">
                                    <div class="mb-3">
                                        <label class="form-label">下载速度</label>
                                        <h4 id="downloadSpeed">0 B/s</h4>
                                    </div>
                                    <div>
                                        <label class="form-label">总下载流量</label>
                                        <h4 id="totalDownload">0 B</h4>
                                    </div>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
            </div>

            <div class="row mb-4">
                <div class="col-md-4">
                    <div class="card">
                        <div class="card-header">
                            <h5 class="card-title mb-0">CPU使用率</h5>
                        </div>
                        <div class="card-body">
                            <h2 id="cpuUsage" class="text-center mb-3">0%</h2>
                            <div class="progress">
                                <div id="cpuProgressBar" class="progress-bar" role="progressbar" style="width: 0%"></div>
                            </div>
                        </div>
                    </div>
                </div>
                <div class="col-md-4">
                    <div class="card">
                        <div class="card-header">
                            <h5 class="card-title mb-0">内存使用率</h5>
                        </div>
                        <div class="card-body">
                            <h2 id="memoryUsage" class="text-center mb-3">0%</h2>
                            <div class="progress mb-3">
                                <div id="memoryProgressBar" class="progress-bar bg-success" role="progressbar" style="width: 0%"></div>
                            </div>
                            <div class="text-center">
                                <span id="memoryUsedValue">0</span> MB / <span id="memoryTotalValue">0</span> MB
                            </div>
                        </div>
                    </div>
                </div>
                <div class="col-md-4">
                    <div class="card">
                        <div class="card-header">
                            <h5 class="card-title mb-0">硬盘使用率</h5>
                        </div>
                        <div class="card-body">
                            <h2 id="diskUsage" class="text-center mb-3">0%</h2>
                            <div class="progress mb-3">
                                <div id="diskProgressBar" class="progress-bar bg-info" role="progressbar" style="width: 0%"></div>
                            </div>
                            <div class="text-center">
                                <span id="diskUsedValue">0</span> GB / <span id="diskTotalValue">0</span> GB
                            </div>
                        </div>
                    </div>
                </div>
            </div>

            <div class="row">
                <div class="col-md-4">
                    <div class="card">
                        <div class="card-header">
                            <h5 class="card-title mb-0">CPU历史</h5>
                        </div>
                        <div class="card-body">
                            <div class="chart-container">
                                <canvas id="cpuChart"></canvas>
                            </div>
                        </div>
                    </div>
                </div>
                <div class="col-md-4">
                    <div class="card">
                        <div class="card-header">
                            <h5 class="card-title mb-0">内存历史</h5>
                        </div>
                        <div class="card-body">
                            <div class="chart-container">
                                <canvas id="memoryChart"></canvas>
                            </div>
                        </div>
                    </div>
                </div>
                <div class="col-md-4">
                    <div class="card">
                        <div class="card-header">
                            <h5 class="card-title mb-0">网络历史</h5>
                        </div>
                        <div class="card-body">
                            <div class="chart-container">
                                <canvas id="networkChart"></canvas>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </div>

    <footer class="footer mt-5 py-3 bg-light">
        <div class="container text-center">
            <span class="text-muted">VPS监控面板 &copy; 2025</span>
        </div>
    </footer>

    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/js/bootstrap.bundle.min.js"></script>
    <script src="/js/main.js"></script>
</body>
</html>`;
}

function getLoginHtml() {
  return `<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>登录 - VPS监控面板</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css" rel="stylesheet">
    <link href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.8.1/font/bootstrap-icons.css" rel="stylesheet">
    <link href="/css/style.css" rel="stylesheet">
</head>
<body>
    <nav class="navbar navbar-expand-lg navbar-dark bg-primary">
        <div class="container">
            <a class="navbar-brand" href="/">VPS监控面板</a>
            <button class="navbar-toggler" type="button" data-bs-toggle="collapse" data-bs-target="#navbarNav">
                <span class="navbar-toggler-icon"></span>
            </button>
            <div class="collapse navbar-collapse" id="navbarNav">
                <ul class="navbar-nav ms-auto">
                    <li class="nav-item">
                        <a class="nav-link" href="/">返回首页</a>
                    </li>
                </ul>
            </div>
        </div>
    </nav>

    <div class="container mt-5">
        <div class="row justify-content-center">
            <div class="col-md-6 col-lg-4">
                <div class="card">
                    <div class="card-header">
                        <h4 class="card-title mb-0">管理员登录</h4>
                    </div>
                    <div class="card-body">
                        <div id="loginAlert" class="alert alert-danger d-none"></div>
                        <form id="loginForm">
                            <div class="mb-3">
                                <label for="username" class="form-label">用户名</label>
                                <input type="text" class="form-control" id="username" required>
                            </div>
                            <div class="mb-3">
                                <label for="password" class="form-label">密码</label>
                                <input type="password" class="form-control" id="password" required>
                            </div>
                            <div class="d-grid">
                                <button type="submit" class="btn btn-primary">登录</button>
                            </div>
                        </form>
                    </div>
                    <div class="card-footer text-muted">
                        <small>初始账号密码: admin / admin</small>
                    </div>
                </div>
            </div>
        </div>
    </div>

    <footer class="footer mt-5 py-3 bg-light">
        <div class="container text-center">
            <span class="text-muted">VPS监控面板 &copy; 2025</span>
        </div>
    </footer>

    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/js/bootstrap.bundle.min.js"></script>
    <script src="/js/login.js"></script>
</body>
</html>`;
}

function getAdminHtml() {
  return `<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>管理后台 - VPS监控面板</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css" rel="stylesheet">
    <link href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.8.1/font/bootstrap-icons.css" rel="stylesheet">
    <link href="/css/style.css" rel="stylesheet">
</head>
<body>
    <nav class="navbar navbar-expand-lg navbar-dark bg-primary">
        <div class="container">
            <a class="navbar-brand" href="/">VPS监控面板</a>
            <button class="navbar-toggler" type="button" data-bs-toggle="collapse" data-bs-target="#navbarNav">
                <span class="navbar-toggler-icon"></span>
            </button>
            <div class="collapse navbar-collapse" id="navbarNav">
                <ul class="navbar-nav me-auto">
                    <li class="nav-item">
                        <a class="nav-link" href="/">返回首页</a>
                    </li>
                </ul>
                <ul class="navbar-nav">
                    <li class="nav-item">
                        <button id="changePasswordBtn" class="btn btn-outline-light btn-sm me-2">修改密码</button>
                    </li>
                    <li class="nav-item">
                        <button id="logoutBtn" class="btn btn-outline-light btn-sm">退出登录</button>
                    </li>
                </ul>
            </div>
        </div>
    </nav>

    <div class="container mt-4">
        <div class="d-flex justify-content-between align-items-center mb-4">
            <h2>服务器管理</h2>
            <button id="addServerBtn" class="btn btn-primary">
                <i class="bi bi-plus-circle"></i> 添加服务器
            </button>
        </div>

        <div id="serverAlert" class="alert d-none"></div>

        <div class="card">
            <div class="card-body">
                <div class="table-responsive">
                    <table class="table table-striped table-hover">
                        <thead>
                            <tr>
                                <th>ID</th>
                                <th>名称</th>
                                <th>描述</th>
                                <th>API密钥</th>
                                <th>状态</th>
                                <th>最后更新</th>
                                <th>操作</th>
                            </tr>
                        </thead>
                        <tbody id="serverTableBody">
                            <tr>
                                <td colspan="7" class="text-center">加载中...</td>
                            </tr>
                        </tbody>
                    </table>
                </div>
            </div>
        </div>
    </div>

    <!-- 服务器模态框 -->
    <div class="modal fade" id="serverModal" tabindex="-1">
        <div class="modal-dialog">
            <div class="modal-content">
                <div class="modal-header">
                    <h5 class="modal-title" id="serverModalTitle">添加服务器</h5>
                    <button type="button" class="btn-close" data-bs-dismiss="modal"></button>
                </div>
                <div class="modal-body">
                    <form id="serverForm">
                        <input type="hidden" id="serverId">
                        <div class="mb-3">
                            <label for="serverName" class="form-label">服务器名称</label>
                            <input type="text" class="form-control" id="serverName" required>
                        </div>
                        <div class="mb-3">
                            <label for="serverDescription" class="form-label">描述（可选）</label>
                            <textarea class="form-control" id="serverDescription" rows="2"></textarea>
                        </div>
                        <div id="apiKeyGroup" class="mb-3 d-none">
                            <label for="apiKey" class="form-label">API密钥</label>
                            <div class="input-group">
                                <input type="text" class="form-control" id="apiKey" readonly>
                                <button class="btn btn-outline-secondary" type="button" id="copyApiKeyBtn">
                                    <i class="bi bi-clipboard"></i>
                                </button>
                            </div>
                            <div class="form-text text-danger">请保存此密钥，它只会显示一次！</div>
                        </div>
                    </form>
                </div>
                <div class="modal-footer">
                    <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">关闭</button>
                    <button type="button" class="btn btn-primary" id="saveServerBtn">保存</button>
                </div>
            </div>
        </div>
    </div>

    <!-- 删除确认模态框 -->
    <div class="modal fade" id="deleteModal" tabindex="-1">
        <div class="modal-dialog">
            <div class="modal-content">
                <div class="modal-header">
                    <h5 class="modal-title">确认删除</h5>
                    <button type="button" class="btn-close" data-bs-dismiss="modal"></button>
                </div>
                <div class="modal-body">
                    <p>确定要删除服务器 "<span id="deleteServerName"></span>" 吗？</p>
                    <p class="text-danger">此操作不可逆，所有相关的监控数据也将被删除。</p>
                </div>
                <div class="modal-footer">
                    <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">取消</button>
                    <button type="button" class="btn btn-danger" id="confirmDeleteBtn">删除</button>
                </div>
            </div>
        </div>
    </div>

    <!-- 修改密码模态框 -->
    <div class="modal fade" id="passwordModal" tabindex="-1">
        <div class="modal-dialog">
            <div class="modal-content">
                <div class="modal-header">
                    <h5 class="modal-title">修改密码</h5>
                    <button type="button" class="btn-close" data-bs-dismiss="modal"></button>
                </div>
                <div class="modal-body">
                    <div id="passwordAlert" class="alert d-none"></div>
                    <form id="passwordForm">
                        <div class="mb-3">
                            <label for="currentPassword" class="form-label">当前密码</label>
                            <input type="password" class="form-control" id="currentPassword" required>
                        </div>
                        <div class="mb-3">
                            <label for="newPassword" class="form-label">新密码</label>
                            <input type="password" class="form-control" id="newPassword" required>
                        </div>
                        <div class="mb-3">
                            <label for="confirmPassword" class="form-label">确认新密码</label>
                            <input type="password" class="form-control" id="confirmPassword" required>
                        </div>
                    </form>
                </div>
                <div class="modal-footer">
                    <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">取消</button>
                    <button type="button" class="btn btn-primary" id="savePasswordBtn">保存</button>
                </div>
            </div>
        </div>
    </div>

    <footer class="footer mt-5 py-3 bg-light">
        <div class="container text-center">
            <span class="text-muted">VPS监控面板 &copy; 2025</span>
        </div>
    </footer>

    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/js/bootstrap.bundle.min.js"></script>
    <script src="/js/admin.js"></script>
</body>
</html>`;
}

function getStyleCss() {
  return `/* 全局样式 */
body {
    min-height: 100vh;
    display: flex;
    flex-direction: column;
}

.footer {
    margin-top: auto;
}

/* 图表容器 */
.chart-container {
    position: relative;
    height: 200px;
    width: 100%;
}

/* 卡片样式 */
.card {
    box-shadow: 0 0.125rem 0.25rem rgba(0, 0, 0, 0.075);
    margin-bottom: 1.5rem;
}

.card-header {
    background-color: rgba(0, 0, 0, 0.03);
    border-bottom: 1px solid rgba(0, 0, 0, 0.125);
}

/* 进度条样式 */
.progress {
    height: 0.75rem;
}

/* 表格样式 */
.table th {
    font-weight: 600;
}

/* 响应式调整 */
@media (max-width: 768px) {
    .chart-container {
        height: 150px;
    }
}`;
}

function getMainJs() {
  return `// main.js - 首页面的JavaScript逻辑

// 全局变量
let currentServerId = null;
let cpuChart = null;
let memoryChart = null;
let networkChart = null;
let cpuData = [];
let memoryData = [];
let networkData = [];
let updateInterval = null;

// 页面加载完成后执行
document.addEventListener('DOMContentLoaded', function() {
    // 初始化服务器列表
    fetchServersList();
    
    // 设置服务器选择器的事件监听
    document.getElementById('serverList').addEventListener('click', function(e) {
        if (e.target.classList.contains('dropdown-item')) {
            const serverId = e.target.getAttribute('data-id');
            const serverName = e.target.textContent;
            selectServer(serverId, serverName);
        }
    });
});

// 获取服务器列表
async function fetchServersList() {
    try {
        const response = await fetch('/api/servers');
        if (!response.ok) {
            throw new Error('获取服务器列表失败');
        }
        
        const data = await response.json();
        const serverList = document.getElementById('serverList');
        serverList.innerHTML = '';
        
        if (data.servers && data.servers.length > 0) {
            data.servers.forEach(server => {
                const item = document.createElement('li');
                const link = document.createElement('a');
                link.classList.add('dropdown-item');
                link.setAttribute('data-id', server.id);
                link.textContent = server.name;
                item.appendChild(link);
                serverList.appendChild(item);
            });
            
            // 默认选择第一个服务器
            selectServer(data.servers[0].id, data.servers[0].name);
        } else {
            // 没有服务器数据
            document.getElementById('serverSelector').textContent = '无服务器数据';
            document.getElementById('noServers').classList.remove('d-none');
            document.getElementById('serverData').classList.add('d-none');
        }
    } catch (error) {
        console.error('获取服务器列表错误:', error);
        document.getElementById('serverSelector').textContent = '加载失败';
        document.getElementById('noServers').classList.remove('d-none');
        document.getElementById('serverData').classList.add('d-none');
        document.getElementById('noServers').textContent = '加载服务器列表失败，请刷新页面重试。';
    }
}

// 选择服务器
function selectServer(serverId, serverName) {
    // 清除之前的更新定时器
    if (updateInterval) {
        clearInterval(updateInterval);
    }
    
    // 更新当前选中的服务器
    currentServerId = serverId;
    document.getElementById('serverSelector').textContent = serverName;
    
    // 显示服务器数据区域
    document.getElementById('noServers').classList.add('d-none');
    document.getElementById('serverData').classList.remove('d-none');
    
    // 初始化图表
    initCharts();
    
    // 获取服务器数据
    fetchServerData(serverId);
    
    // 设置定时更新
    updateInterval = setInterval(() => {
        fetchServerData(serverId);
    }, 5000); // 每5秒更新一次
}

// 初始化图表
function initCharts() {
    // 销毁已存在的图表
    if (cpuChart) cpuChart.destroy();
    if (memoryChart) memoryChart.destroy();
    if (networkChart) networkChart.destroy();
    
    // 重置数据数组
    cpuData = [];
    memoryData = [];
    networkData = [];
    
    // 图表配置
    const chartOptions = {
        responsive: true,
        maintainAspectRatio: false,
        animation: {
            duration: 500
        },
        scales: {
            x: {
                grid: {
                    display: false
                }
            },
            y: {
                beginAtZero: true,
                grid: {
                    color: 'rgba(0, 0, 0, 0.05)'
                }
            }
        },
        plugins: {
            legend: {
                position: 'top'
            }
        }
    };
    
    // CPU图表
    const cpuCtx = document.getElementById('cpuChart').getContext('2d');
    cpuChart = new Chart(cpuCtx, {
        type: 'line',
        data: {
            labels: [],
            datasets: [{
                label: 'CPU使用率 (%)',
                data: [],
                borderColor: '#0d6efd',
                backgroundColor: 'rgba(13, 110, 253, 0.1)',
                borderWidth: 2,
                fill: true,
                tension: 0.4
            }]
        },
        options: {
            ...chartOptions,
            scales: {
                ...chartOptions.scales,
                y: {
                    ...chartOptions.scales.y,
                    max: 100
                }
            }
        }
    });
    
    // 内存图表
    const memoryCtx = document.getElementById('memoryChart').getContext('2d');
    memoryChart = new Chart(memoryCtx, {
        type: 'line',
        data: {
            labels: [],
            datasets: [{
                label: '内存使用率 (%)',
                data: [],
                borderColor: '#198754',
                backgroundColor: 'rgba(25, 135, 84, 0.1)',
                borderWidth: 2,
                fill: true,
                tension: 0.4
            }]
        },
        options: {
            ...chartOptions,
            scales: {
                ...chartOptions.scales,
                y: {
                    ...chartOptions.scales.y,
                    max: 100
                }
            }
        }
    });
    
    // 网络图表
    const networkCtx = document.getElementById('networkChart').getContext('2d');
    networkChart = new Chart(networkCtx, {
        type: 'line',
        data: {
            labels: [],
            datasets: [
                {
                    label: '下载速度 (KB/s)',
                    data: [],
                    borderColor: '#0dcaf0',
                    backgroundColor: 'rgba(13, 202, 240, 0.1)',
                    borderWidth: 2,
                    fill: false,
                    tension: 0.4
                },
                {
                    label: '上传速度 (KB/s)',
                    data: [],
                    borderColor: '#ffc107',
                    backgroundColor: 'rgba(255, 193, 7, 0.1)',
                    borderWidth: 2,
                    fill: false,
                    tension: 0.4
                }
            ]
        },
        options: chartOptions
    });
}

// 获取服务器数据
async function fetchServerData(serverId) {
    try {
        const response = await fetch(\`/api/status/\${serverId}\`);
        if (!response.ok) {
            throw new Error('获取服务器数据失败');
        }
        
        const data = await response.json();
        updateDashboard(data);
    } catch (error) {
        console.error('获取服务器数据错误:', error);
        document.getElementById('serverStatus').textContent = '离线';
        document.getElementById('serverStatus').className = 'badge bg-danger';
    }
}

// 更新仪表盘数据
function updateDashboard(data) {
    if (!data || !data.metrics) {
        console.error('无效的服务器数据');
        return;
    }
    
    const metrics = data.metrics;
    const serverInfo = data.server;
    
    // 更新服务器信息
    document.getElementById('serverName').textContent = serverInfo.name;
    document.getElementById('serverDescription').textContent = serverInfo.description || '无描述';
    document.getElementById('lastUpdate').textContent = new Date(metrics.timestamp * 1000).toLocaleString();
    document.getElementById('serverStatus').textContent = '在线';
    document.getElementById('serverStatus').className = 'badge bg-success';
    
    // 更新CPU数据
    const cpuUsage = metrics.cpu.usage_percent.toFixed(1);
    document.getElementById('cpuUsage').textContent = \`\${cpuUsage}%\`;
    document.getElementById('cpuProgressBar').style.width = \`\${cpuUsage}%\`;
    
    // 更新内存数据
    const memoryUsage = metrics.memory.usage_percent.toFixed(1);
    const memoryTotal = (metrics.memory.total / 1024).toFixed(0); // 转换为MB
    const memoryUsed = (metrics.memory.used / 1024).toFixed(0); // 转换为MB
    document.getElementById('memoryUsage').textContent = \`\${memoryUsage}%\`;
    document.getElementById('memoryProgressBar').style.width = \`\${memoryUsage}%\`;
    document.getElementById('memoryTotalValue').textContent = memoryTotal;
    document.getElementById('memoryUsedValue').textContent = memoryUsed;
    
    // 更新硬盘数据
    const diskUsage = metrics.disk.usage_percent.toFixed(1);
    document.getElementById('diskUsage').textContent = \`\${diskUsage}%\`;
    document.getElementById('diskProgressBar').style.width = \`\${diskUsage}%\`;
    document.getElementById('diskTotalValue').textContent = metrics.disk.total.toFixed(0);
    document.getElementById('diskUsedValue').textContent = metrics.disk.used.toFixed(0);
    
    // 更新网络速度
    const uploadSpeed = formatNetworkSpeed(metrics.network.upload_speed);
    const downloadSpeed = formatNetworkSpeed(metrics.network.download_speed);
    document.getElementById('uploadSpeed').textContent = uploadSpeed;
    document.getElementById('downloadSpeed').textContent = downloadSpeed;
    
    // 更新总流量
    const totalUpload = formatDataSize(metrics.network.total_upload);
    const totalDownload = formatDataSize(metrics.network.total_download);
    document.getElementById('totalUpload').textContent = totalUpload;
    document.getElementById('totalDownload').textContent = totalDownload;
    
    // 更新图表数据
    updateCharts(metrics);
}

// 更新图表数据
function updateCharts(metrics) {
    const time = new Date(metrics.timestamp * 1000).toLocaleTimeString();
    
    // 限制数据点数量
    const maxDataPoints = 10;
    
    // 更新CPU图表
    cpuData.push({
        x: time,
        y: metrics.cpu.usage_percent
    });
    
    if (cpuData.length > maxDataPoints) {
        cpuData.shift();
    }
    
    cpuChart.data.labels = cpuData.map(point => point.x);
    cpuChart.data.datasets[0].data = cpuData.map(point => point.y);
    cpuChart.update();
    
    // 更新内存图表
    memoryData.push({
        x: time,
        y: metrics.memory.usage_percent
    });
    
    if (memoryData.length > maxDataPoints) {
        memoryData.shift();
    }
    
    memoryChart.data.labels = memoryData.map(point => point.x);
    memoryChart.data.datasets[0].data = memoryData.map(point => point.y);
    memoryChart.update();
    
    // 更新网络图表
    networkData.push({
        x: time,
        download: metrics.network.download_speed / 1024, // 转换为KB/s
        upload: metrics.network.upload_speed / 1024 // 转换为KB/s
    });
    
    if (networkData.length > maxDataPoints) {
        networkData.shift();
    }
    
    networkChart.data.labels = networkData.map(point => point.x);
    networkChart.data.datasets[0].data = networkData.map(point => point.download);
    networkChart.data.datasets[1].data = networkData.map(point => point.upload);
    networkChart.update();
}

// 格式化网络速度
function formatNetworkSpeed(bytesPerSecond) {
    if (bytesPerSecond < 1024) {
        return \`\${bytesPerSecond.toFixed(1)} B/s\`;
    } else if (bytesPerSecond < 1024 * 1024) {
        return \`\${(bytesPerSecond / 1024).toFixed(1)} KB/s\`;
    } else if (bytesPerSecond < 1024 * 1024 * 1024) {
        return \`\${(bytesPerSecond / (1024 * 1024)).toFixed(1)} MB/s\`;
    } else {
        return \`\${(bytesPerSecond / (1024 * 1024 * 1024)).toFixed(1)} GB/s\`;
    }
}

// 格式化数据大小
function formatDataSize(bytes) {
    if (bytes < 1024) {
        return \`\${bytes.toFixed(1)} B\`;
    } else if (bytes < 1024 * 1024) {
        return \`\${(bytes / 1024).toFixed(1)} KB\`;
    } else if (bytes < 1024 * 1024 * 1024) {
        return \`\${(bytes / (1024 * 1024)).toFixed(1)} MB\`;
    } else if (bytes < 1024 * 1024 * 1024 * 1024) {
        return \`\${(bytes / (1024 * 1024 * 1024)).toFixed(1)} GB\`;
    } else {
        return \`\${(bytes / (1024 * 1024 * 1024 * 1024)).toFixed(1)} TB\`;
    }
}`;
}

function getLoginJs() {
  return `// login.js - 登录页面的JavaScript逻辑

// 页面加载完成后执行
document.addEventListener('DOMContentLoaded', function() {
    // 获取登录表单元素
    const loginForm = document.getElementById('loginForm');
    const loginAlert = document.getElementById('loginAlert');
    
    // 添加表单提交事件监听
    loginForm.addEventListener('submit', function(e) {
        e.preventDefault();
        
        // 获取用户输入
        const username = document.getElementById('username').value.trim();
        const password = document.getElementById('password').value.trim();
        
        // 验证输入
        if (!username || !password) {
            showLoginError('请输入用户名和密码');
            return;
        }
        
        // 执行登录
        login(username, password);
    });
    
    // 检查是否已登录
    checkLoginStatus();
});

// 检查登录状态
async function checkLoginStatus() {
    try {
        // 从localStorage获取token
        const token = localStorage.getItem('auth_token');
        if (!token) {
            return;
        }
        
        const response = await fetch('/api/auth/status', {
            headers: {
                'Authorization': \`Bearer \${token}\`
            }
        });
        
        if (response.ok) {
            const data = await response.json();
            if (data.authenticated) {
                // 已登录，重定向到管理后台
                window.location.href = 'admin.html';
            }
        }
    } catch (error) {
        console.error('检查登录状态错误:', error);
    }
}

// 登录函数
async function login(username, password) {
    try {
        // 显示加载状态
        const submitBtn = loginForm.querySelector('button[type="submit"]');
        const originalBtnText = submitBtn.innerHTML;
        submitBtn.disabled = true;
        submitBtn.innerHTML = '<span class="spinner-border spinner-border-sm" role="status" aria-hidden="true"></span> 登录中...';
        
        // 发送登录请求
        const response = await fetch('/api/auth/login', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ username, password })
        });
        
        // 恢复按钮状态
        submitBtn.disabled = false;
        submitBtn.innerHTML = originalBtnText;
        
        if (response.ok) {
            const data = await response.json();
            // 保存token到localStorage
            localStorage.setItem('auth_token', data.token);
            // 登录成功，重定向到管理后台
            window.location.href = 'admin.html';
        } else {
            // 登录失败
            const data = await response.json();
            showLoginError(data.message || '用户名或密码错误');
        }
    } catch (error) {
        console.error('登录错误:', error);
        showLoginError('登录请求失败，请稍后重试');
    }
}

// 显示登录错误
function showLoginError(message) {
    const loginAlert = document.getElementById('loginAlert');
    loginAlert.textContent = message;
    loginAlert.classList.remove('d-none');
    
    // 5秒后自动隐藏错误信息
    setTimeout(() => {
        loginAlert.classList.add('d-none');
    }, 5000);
}`;
}

function getAdminJs() {
  return `// admin.js - 管理后台的JavaScript逻辑

// 全局变量
let currentServerId = null;
let serverList = [];

// 页面加载完成后执行
document.addEventListener('DOMContentLoaded', function() {
    // 检查登录状态
    checkLoginStatus();
    
    // 初始化事件监听
    initEventListeners();
    
    // 加载服务器列表
    loadServerList();
});

// 检查登录状态
async function checkLoginStatus() {
    try {
        // 从localStorage获取token
        const token = localStorage.getItem('auth_token');
        if (!token) {
            // 未登录，重定向到登录页面
            window.location.href = 'login.html';
            return;
        }
        
        const response = await fetch('/api/auth/status', {
            headers: {
                'Authorization': \`Bearer \${token}\`
            }
        });
        
        if (response.ok) {
            const data = await response.json();
            if (!data.authenticated) {
                // 未登录，重定向到登录页面
                window.location.href = 'login.html';
            }
        } else {
            // 请求失败，重定向到登录页面
            window.location.href = 'login.html';
        }
    } catch (error) {
        console.error('检查登录状态错误:', error);
        window.location.href = 'login.html';
    }
}

// 初始化事件监听
function initEventListeners() {
    // 添加服务器按钮
    document.getElementById('addServerBtn').addEventListener('click', function() {
        showServerModal();
    });
    
    // 保存服务器按钮
    document.getElementById('saveServerBtn').addEventListener('click', function() {
        saveServer();
    });
    
    // 复制API密钥按钮
    document.getElementById('copyApiKeyBtn').addEventListener('click', function() {
        const apiKeyInput = document.getElementById('apiKey');
        apiKeyInput.select();
        document.execCommand('copy');
        
        // 显示复制成功提示
        const copyBtn = document.getElementById('copyApiKeyBtn');
        const originalHtml = copyBtn.innerHTML;
        copyBtn.innerHTML = '<i class="bi bi-check"></i>';
        copyBtn.classList.add('btn-success');
        copyBtn.classList.remove('btn-outline-secondary');
        
        setTimeout(() => {
            copyBtn.innerHTML = originalHtml;
            copyBtn.classList.remove('btn-success');
            copyBtn.classList.add('btn-outline-secondary');
        }, 2000);
    });
    
    // 确认删除按钮
    document.getElementById('confirmDeleteBtn').addEventListener('click', function() {
        if (currentServerId) {
            deleteServer(currentServerId);
        }
    });
    
    // 修改密码按钮
    document.getElementById('changePasswordBtn').addEventListener('click', function() {
        showPasswordModal();
    });
    
    // 保存密码按钮
    document.getElementById('savePasswordBtn').addEventListener('click', function() {
        changePassword();
    });
    
    // 退出登录按钮
    document.getElementById('logoutBtn').addEventListener('click', function() {
        logout();
    });
}

// 获取认证头
function getAuthHeaders() {
    const token = localStorage.getItem('auth_token');
    return {
        'Content-Type': 'application/json',
        'Authorization': \`Bearer \${token}\`
    };
}

// 加载服务器列表
async function loadServerList() {
    try {
        const response = await fetch('/api/admin/servers', {
            headers: getAuthHeaders()
        });
        
        if (!response.ok) {
            throw new Error('获取服务器列表失败');
        }
        
        const data = await response.json();
        serverList = data.servers || [];
        
        renderServerTable(serverList);
    } catch (error) {
        console.error('加载服务器列表错误:', error);
        showAlert('danger', '加载服务器列表失败，请刷新页面重试。');
    }
}

// 渲染服务器表格
function renderServerTable(servers) {
    const tableBody = document.getElementById('serverTableBody');
    tableBody.innerHTML = '';
    
    if (servers.length === 0) {
        const row = document.createElement('tr');
        row.innerHTML = '<td colspan="7" class="text-center">暂无服务器数据</td>';
        tableBody.appendChild(row);
        return;
    }
    
    servers.forEach(server => {
        const row = document.createElement('tr');
        
        // 格式化最后更新时间
        let lastUpdateText = '从未';
        let statusBadge = '<span class="badge bg-secondary">未知</span>';
        
        if (server.last_report) {
            const lastUpdate = new Date(server.last_report * 1000);
            lastUpdateText = lastUpdate.toLocaleString();
            
            // 检查是否在线（最后报告时间在10分钟内）
            const now = new Date();
            const diffMinutes = (now - lastUpdate) / (1000 * 60);
            
            if (diffMinutes <= 10) {
                statusBadge = '<span class="badge bg-success">在线</span>';
            } else {
                statusBadge = '<span class="badge bg-danger">离线</span>';
            }
        }
        
        row.innerHTML = \`
            <td>\${server.id}</td>
            <td>\${server.name}</td>
            <td>\${server.description || '-'}</td>
            <td>
                <button class="btn btn-sm btn-outline-secondary view-key-btn" data-id="\${server.id}">
                    <i class="bi bi-key"></i> 查看密钥
                </button>
            </td>
            <td>\${statusBadge}</td>
            <td>\${lastUpdateText}</td>
            <td>
                <div class="btn-group">
                    <button class="btn btn-sm btn-outline-primary edit-server-btn" data-id="\${server.id}">
                        <i class="bi bi-pencil"></i>
                    </button>
                    <button class="btn btn-sm btn-outline-danger delete-server-btn" data-id="\${server.id}" data-name="\${server.name}">
                        <i class="bi bi-trash"></i>
                    </button>
                </div>
            </td>
        \`;
        
        tableBody.appendChild(row);
    });
    
    // 添加事件监听
    document.querySelectorAll('.view-key-btn').forEach(btn => {
        btn.addEventListener('click', function() {
            const serverId = this.getAttribute('data-id');
            viewApiKey(serverId);
        });
    });
    
    document.querySelectorAll('.edit-server-btn').forEach(btn => {
        btn.addEventListener('click', function() {
            const serverId = this.getAttribute('data-id');
            editServer(serverId);
        });
    });
    
    document.querySelectorAll('.delete-server-btn').forEach(btn => {
        btn.addEventListener('click', function() {
            const serverId = this.getAttribute('data-id');
            const serverName = this.getAttribute('data-name');
            showDeleteConfirmation(serverId, serverName);
        });
    });
}

// 显示服务器模态框（添加模式）
function showServerModal() {
    // 重置表单
    document.getElementById('serverForm').reset();
    document.getElementById('serverId').value = '';
    document.getElementById('apiKeyGroup').classList.add('d-none');
    
    // 设置模态框标题
    document.getElementById('serverModalTitle').textContent = '添加服务器';
    
    // 显示模态框
    const serverModal = new bootstrap.Modal(document.getElementById('serverModal'));
    serverModal.show();
}

// 编辑服务器
function editServer(serverId) {
    const server = serverList.find(s => s.id === serverId);
    if (!server) return;
    
    // 填充表单
    document.getElementById('serverId').value = server.id;
    document.getElementById('serverName').value = server.name;
    document.getElementById('serverDescription').value = server.description || '';
    document.getElementById('apiKeyGroup').classList.add('d-none');
    
    // 设置模态框标题
    document.getElementById('serverModalTitle').textContent = '编辑服务器';
    
    // 显示模态框
    const serverModal = new bootstrap.Modal(document.getElementById('serverModal'));
    serverModal.show();
}

// 保存服务器
async function saveServer() {
    const serverId = document.getElementById('serverId').value;
    const serverName = document.getElementById('serverName').value.trim();
    const serverDescription = document.getElementById('serverDescription').value.trim();
    
    if (!serverName) {
        showAlert('danger', '服务器名称不能为空');
        return;
    }
    
    try {
        let response;
        let data;
        
        if (serverId) {
            // 更新服务器
            response = await fetch(\`/api/admin/servers/\${serverId}\`, {
                method: 'PUT',
                headers: getAuthHeaders(),
                body: JSON.stringify({
                    name: serverName,
                    description: serverDescription
                })
            });
        } else {
            // 添加服务器
            response = await fetch('/api/admin/servers', {
                method: 'POST',
                headers: getAuthHeaders(),
                body: JSON.stringify({
                    name: serverName,
                    description: serverDescription
                })
            });
        }
        
        if (!response.ok) {
            throw new Error('保存服务器失败');
        }
        
        data = await response.json();
        
        // 隐藏模态框
        const serverModal = bootstrap.Modal.getInstance(document.getElementById('serverModal'));
        serverModal.hide();
        
        // 如果是新添加的服务器，显示API密钥
        if (!serverId && data.server && data.server.api_key) {
            showApiKey(data.server.id, data.server.api_key);
        } else {
            // 重新加载服务器列表
            loadServerList();
            showAlert('success', serverId ? '服务器更新成功' : '服务器添加成功');
        }
    } catch (error) {
        console.error('保存服务器错误:', error);
        showAlert('danger', '保存服务器失败，请稍后重试');
    }
}

// 查看API密钥
async function viewApiKey(serverId) {
    try {
        const response = await fetch(\`/api/admin/servers/\${serverId}/key\`, {
            headers: getAuthHeaders()
        });
        
        if (!response.ok) {
            throw new Error('获取API密钥失败');
        }
        
        const data = await response.json();
        if (data.api_key) {
            showApiKey(serverId, data.api_key);
        } else {
            showAlert('danger', '获取API密钥失败');
        }
    } catch (error) {
        console.error('查看API密钥错误:', error);
        showAlert('danger', '获取API密钥失败，请稍后重试');
    }
}

// 显示API密钥
function showApiKey(serverId, apiKey) {
    const server = serverList.find(s => s.id === serverId) || { name: '新服务器' };
    
    // 填充表单
    document.getElementById('serverId').value = serverId;
    document.getElementById('serverName').value = server.name;
    document.getElementById('serverDescription').value = server.description || '';
    document.getElementById('apiKey').value = apiKey;
    document.getElementById('apiKeyGroup').classList.remove('d-none');
    
    // 设置模态框标题
    document.getElementById('serverModalTitle').textContent = 'API密钥';
    
    // 显示模态框
    const serverModal = new bootstrap.Modal(document.getElementById('serverModal'));
    serverModal.show();
}

// 显示删除确认
function showDeleteConfirmation(serverId, serverName) {
    currentServerId = serverId;
    document.getElementById('deleteServerName').textContent = serverName;
    
    const deleteModal = new bootstrap.Modal(document.getElementById('deleteModal'));
    deleteModal.show();
}

// 删除服务器
async function deleteServer(serverId) {
    try {
        const response = await fetch(\`/api/admin/servers/\${serverId}\`, {
            method: 'DELETE',
            headers: getAuthHeaders()
        });
        
        if (!response.ok) {
            throw new Error('删除服务器失败');
        }
        
        // 隐藏模态框
        const deleteModal = bootstrap.Modal.getInstance(document.getElementById('deleteModal'));
        deleteModal.hide();
        
        // 重新加载服务器列表
        loadServerList();
        showAlert('success', '服务器删除成功');
    } catch (error) {
        console.error('删除服务器错误:', error);
        showAlert('danger', '删除服务器失败，请稍后重试');
    }
}

// 显示密码修改模态框
function showPasswordModal() {
    // 重置表单
    document.getElementById('passwordForm').reset();
    document.getElementById('passwordAlert').classList.add('d-none');
    
    const passwordModal = new bootstrap.Modal(document.getElementById('passwordModal'));
    passwordModal.show();
}

// 修改密码
async function changePassword() {
    const currentPassword = document.getElementById('currentPassword').value;
    const newPassword = document.getElementById('newPassword').value;
    const confirmPassword = document.getElementById('confirmPassword').value;
    
    // 验证输入
    if (!currentPassword || !newPassword || !confirmPassword) {
        showPasswordAlert('danger', '所有密码字段都必须填写');
        return;
    }
    
    if (newPassword !== confirmPassword) {
        showPasswordAlert('danger', '新密码和确认密码不匹配');
        return;
    }
    
    try {
        const response = await fetch('/api/auth/change-password', {
            method: 'POST',
            headers: getAuthHeaders(),
            body: JSON.stringify({
                current_password: currentPassword,
                new_password: newPassword
            })
        });
        
        if (response.ok) {
            // 隐藏模态框
            const passwordModal = bootstrap.Modal.getInstance(document.getElementById('passwordModal'));
            passwordModal.hide();
            
            showAlert('success', '密码修改成功');
        } else {
            const data = await response.json();
            showPasswordAlert('danger', data.message || '密码修改失败');
        }
    } catch (error) {
        console.error('修改密码错误:', error);
        showPasswordAlert('danger', '密码修改请求失败，请稍后重试');
    }
}

// 退出登录
function logout() {
    // 清除localStorage中的token
    localStorage.removeItem('auth_token');
    
    // 重定向到登录页面
    window.location.href = 'login.html';
}

// 显示警告信息
function showAlert(type, message) {
    const alertElement = document.getElementById('serverAlert');
    alertElement.className = \`alert alert-\${type}\`;
    alertElement.textContent = message;
    alertElement.classList.remove('d-none');
    
    // 5秒后自动隐藏
    setTimeout(() => {
        alertElement.classList.add('d-none');
    }, 5000);
}

// 显示密码修改警告信息
function showPasswordAlert(type, message) {
    const alertElement = document.getElementById('passwordAlert');
    alertElement.className = \`alert alert-\${type}\`;
    alertElement.textContent = message;
    alertElement.classList.remove('d-none');
}`;
}
