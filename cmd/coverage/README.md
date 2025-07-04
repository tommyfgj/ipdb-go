# IPv4 覆盖率检查工具

这个工具用于检查IPv4地址空间的覆盖情况，分析中国大陆路由、外国路由和保留地址段的分布情况。

## 功能

- 解析中国大陆路由文件 (`chnroute-ipv4.txt`)
- 解析bird路由配置文件 (`bird_v4.conf`)
- 分析IPv4保留地址段
- 检查IPv4空间覆盖gap
- 生成详细的覆盖统计报告

## 使用方法

```bash
cd cmd/coverage
go run main.go
```

## 输出说明

工具会输出以下信息：

1. **路由段统计**：显示各类路由段的数量
2. **IPv4空间覆盖统计**：显示各类地址的数量和百分比
3. **Gap检查结果**：如果存在未覆盖的IP段，会详细列出

## 退出码

- `0`：完全覆盖，没有gap
- `1`：发现gap或解析错误

## 依赖文件

工具需要以下文件存在：
- `../../output/chnroute-ipv4.txt`：中国大陆路由文件
- `../../output/bird_v4.conf`：bird路由配置文件 