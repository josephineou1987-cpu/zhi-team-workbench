# 致知 · 团队工作台

地址：https://josephineou1987-cpu.github.io/zhi-team-workbench/

GitHub Pages 托管前端，Supabase Edge Function zhi-workbench 和四张 zhi_ 前缀数据库表提供登录与共享记录。密码仅以加盐 PBKDF2 摘要保存在数据库，不在仓库中。

员工仅修改自己的记录；David/吴权为管理员，可查看全员工作并管理规则与分工。会话八小时过期，退出立即撤销。多人并发修改不同记录自动合并，同一记录冲突则保留草稿并提示。共享数据每二十秒刷新。

前端 config.js 仅含公开 API 地址。backend/index.ts 为已部署函数源码；schema.sql 为已应用结构参考，不含账号凭据。

AI 模型、文件上传与后台定时任务尚未接入；报告目前按已提交的记录进行规则汇总。
