# cf-vps-monitor
## 用cloudflare worker搭建的vps探针简易面板
面板示例：https://vps-monitor.abo-vendor289.workers.dev/

前端：![image](https://github.com/user-attachments/assets/9f082014-e32d-484f-b954-db652d7bd275)

后台：![image](https://github.com/user-attachments/assets/de305d42-3e5f-44ae-bb17-f40b5d4e26e8)

VPS端：![image](https://github.com/user-attachments/assets/c0d92ab4-7e9f-4f57-b255-740b6c281926)


# 使用方法：
1. 把worker.js 里的代码复制到cf worker 里部署。
2. 创建3个kv命名空间并绑定到worker。分别是：

    AUTH_STORE

    SERVERS_STORE

    METRICS_STORE
   
   到KV存储和数据库创建3个命名空间
   ![image](https://github.com/user-attachments/assets/3ddb0ea4-9971-436e-98bf-ca5342ff0c3c)
   
   都绑定到worker
   ![image](https://github.com/user-attachments/assets/006f3ae8-ef86-4b3c-9107-c0275be3e9af)


   
5. 部署完毕就可以打开worker链接登录账号，默认账号密码：admin admin, 添加vps，获得vps ID和密钥。
6. 把 enhanced-install.sh 脚本上传到被控vps，并给脚本权限，按照提示安装即可。
7. 注意worker每日10万次额度
## 本人不懂代码，只是爱好折腾，所有代码都是AI写的，有问题也别问我，去问AI还更快。
## 我只提供一下思路，如果又更好的方案请务必@一下我，我去给你star！
