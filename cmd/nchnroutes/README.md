# NCHNRoutes 命令行工具

这是一个统一的命令行工具，用于生成和验证非中国大陆路由配置。

## 安装和使用

### 1. 进入工具目录

```bash
cd cmd/nchnroutes
```

### 2. 下载依赖

```bash
go mod tidy
```

### 3. 使用方法

#### 生成Bird配置文件

```bash
# 基本用法
go run main.go -mode=generate -db=/path/to/city.free.ipdb

# 指定输出目录
go run main.go -mode=generate -db=/path/to/city.free.ipdb -output=./my_output/

# 启用并行处理
go run main.go -mode=generate -db=/path/to/city.free.ipdb -parallel

# 自定义并行worker数量
go run main.go -mode=generate -db=/path/to/city.free.ipdb -parallel -workers=8
```

#### 验证生成的配置文件

```bash
# 验证默认路径的配置文件
go run main.go -mode=validate -db=/path/to/city.free.ipdb

# 指定配置文件路径
go run main.go -mode=validate -db=/path/to/city.free.ipdb -ipv4=./output/bird_v4.conf -ipv6=./output/bird_v6.conf

# 自定义采样数量
go run main.go -mode=validate -db=/path/to/city.free.ipdb -samples=10
```

## 参数说明

### 通用参数

- `-mode`: 运行模式，`generate`（生成）或 `validate`（验证）
- `-db`: IPDB数据库文件路径（必需）

### 生成模式参数

- `-output`: 输出目录，默认为 `./output/`
- `-parallel`: 启用并行处理，默认为 `false`
- `-workers`: 并行worker数量，默认为CPU核心数

### 验证模式参数

- `-ipv4`: IPv4配置文件路径，不指定则使用默认路径 `./output/bird_v4.conf`
- `-ipv6`: IPv6配置文件路径，不指定则使用默认路径 `./output/bird_v6.conf`
- `-samples`: 每个CIDR的采样验证数量，默认为 `5`

## 输出文件

生成模式会创建以下文件：

- `bird_v4.conf` - IPv4 Bird配置文件
- `bird_v6.conf` - IPv6 Bird配置文件

## 示例

### 完整的生成和验证流程

```bash
# 1. 生成配置文件（启用并行处理）
go run main.go -mode=generate -db=../../city.free.ipdb -output=./output/ -parallel

# 2. 验证生成的配置文件
go run main.go -mode=validate -db=../../city.free.ipdb

# 3. 验证特定配置文件并增加采样数量
go run main.go -mode=validate -db=../../city.free.ipdb -ipv4=./output/bird_v4.conf -samples=10
```

### 输出示例

#### 生成模式输出

```
=== 生成Bird配置模式 ===
数据库: ../../city.free.ipdb
输出目录: ./output/
并行模式: 启用 (8个CPU核心)

正在加载IPDB数据库...
数据库信息:
  构建时间: 1640995200
  IP版本: 3 (IPv4) (IPv6)
  节点数量: 1234567
  字段: [country_name region_name city_name]

正在提取IP范围...
原始数据: 50000个IPv4范围, 20000个IPv6范围

正在过滤IP范围（排除中国大陆和私有地址）...
IPv4统计信息:
  总范围数: 50000
  中国大陆(已过滤): 25000
  私有地址(已过滤): 1000
  香港(保留): 100
  澳门(保留): 10
  台湾(保留): 50
  其他地区(保留): 23840
  最终保留: 24000个IPv4范围

正在合并相邻IP段...
合并后: 15000个IPv4段, 8000个IPv6段

正在生成Bird配置...
✅ 生成完成！
配置文件已生成:
  - ./output/bird_v4.conf (15000个IPv4网段)
  - ./output/bird_v6.conf (8000个IPv6网段)
使用了 8 个CPU核心进行并行过滤处理
```

#### 验证模式输出

```
=== 验证Bird配置模式 ===
数据库: ../../city.free.ipdb
采样数量: 5

正在验证 IPv4 配置: ./output/bird_v4.conf
  发现 15000 个CIDR条目
开始验证 15000 个CIDR，每个CIDR采样 5 个IP地址...
进度: 0/15000 (0.0%)
进度: 1000/15000 (6.7%)
...
✅ IPv4 配置验证通过
--------------------------------------------------------------------------------
正在验证 IPv6 配置: ./output/bird_v6.conf
  发现 8000 个CIDR条目
开始验证 8000 个CIDR，每个CIDR采样 5 个IP地址...
✅ IPv6 配置验证通过
--------------------------------------------------------------------------------

🎉 所有配置文件验证通过！
```

## 注意事项

1. 确保IPDB数据库文件路径正确且文件存在
2. 生成的配置文件会排除中国大陆IP地址，但保留香港、澳门、台湾的IP
3. 并行处理可以显著提高大数据集的处理速度，但会消耗更多CPU资源
4. 验证过程中会对每个CIDR进行采样检查，采样数量越大验证越准确但耗时越长
5. 默认输出目录为 `./output/`，如果不存在会自动创建 