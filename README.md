# cf-vps-monitor
## 用cloudflare worker搭建的vps探针简易面板
面板示例：https://vps-monitor.abo-vendor289.workers.dev/

前端：![image](https://github.com/user-attachments/assets/08d7cc6e-0635-4e88-8e29-d5a4591fdb96)

后台：![image](https://github.com/user-attachments/assets/f5e4aaae-ac8d-4d76-89de-fe9ae6a00331)

VPS端：![image](https://github.com/user-attachments/assets/c0d92ab4-7e9f-4f57-b255-740b6c281926)


# 使用方法：
1. 把worker.js 里的代码复制到cf worker 里部署。
2. 创建3个kv存储并绑定到worker。分别是：AUTH_STORE  SERVERS_STORE  METRICS_STORE
3. 部署完毕就可以打开worker链接登录账号，默认账号密码：admin admin, 添加vps，获得vps ID和密钥。
4. 把 enhanced-install.sh 脚本上传到被控vps，并给脚本权限，按照提示安装即可。
5. 注意worker每日10万次额度
## 本人不懂代码，所有代码都是AI写的，有问题也别问我，去问AI还更快。
