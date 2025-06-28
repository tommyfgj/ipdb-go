# NCHNRoutes - 非中国大陆路由生成和验证工具

这个包包含了从IPDB数据库提取非中国大陆IP范围并生成Bird配置文件的核心功能，以及验证生成配置的工具。

## 包结构

- `extractor.go` - IPDB数据库提取器，用于从IPDB文件中提取IP范围
- `filter.go` - IP范围过滤器，用于过滤中国大陆IP和私有地址
- `merger.go` - CIDR合并器，用于合并相邻的IP范围
- `output.go` - Bird配置输出器，用于生成Bird路由配置文件
- `validator.go` - IP验证器，用于验证生成的配置文件

## 主要功能

### 1. IP数据库提取器 (IPDBExtractor)

```go
extractor, err := nchnroutes.NewExtractor("path/to/ipdb.db")
if err != nil {
    log.Fatal(err)
}

ipv4Ranges, ipv6Ranges, err := extractor.ExtractAllRanges()
```

### 2. IP范围过滤器

```go
// 串行过滤
filtered, stats := nchnroutes.FilterRanges(ranges)

// 并行过滤
filtered, stats := nchnroutes.FilterRangesParallel(ranges)
```

### 3. CIDR合并器

```go
cidrs := nchnroutes.RangesToCIDRs(ranges)
merged := nchnroutes.MergeCIDRs(cidrs)
```

### 4. Bird配置输出

```go
// 输出IPv4配置
err := nchnroutes.OutputIPv4BirdConfig(ipv4CIDRs, "bird_v4.conf")

// 输出IPv6配置
err := nchnroutes.OutputIPv6BirdConfig(ipv6CIDRs, "bird_v6.conf")
```

### 5. IP验证器

```go
validator, err := nchnroutes.NewIPValidator("path/to/ipdb.db", 5)
if err != nil {
    log.Fatal(err)
}

cidrs, err := validator.ExtractCIDRsFromBirdConfig("bird_v4.conf")
validator.ValidateCIDRs(cidrs)
validator.GenerateReport()
```

## 使用示例

### 生成Bird配置文件

```go
package main

import (
    "log"
    "github.com/ipipdotnet/ipdb-go/nchnroutes"
)

func main() {
    // 1. 加载IPDB数据库
    extractor, err := nchnroutes.NewExtractor("city.free.ipdb")
    if err != nil {
        log.Fatal(err)
    }

    // 2. 提取IP范围
    ipv4Ranges, ipv6Ranges, err := extractor.ExtractAllRanges()
    if err != nil {
        log.Fatal(err)
    }

    // 3. 过滤IP范围（排除中国大陆和私有地址）
    filteredIPv4, _ := nchnroutes.FilterRanges(ipv4Ranges)
    filteredIPv6, _ := nchnroutes.FilterRanges(ipv6Ranges)

    // 4. 合并相邻CIDR
    ipv4CIDRs := nchnroutes.MergeCIDRs(nchnroutes.RangesToCIDRs(filteredIPv4))
    ipv6CIDRs := nchnroutes.MergeCIDRs(nchnroutes.RangesToCIDRs(filteredIPv6))

    // 5. 生成Bird配置文件
    nchnroutes.OutputIPv4BirdConfig(ipv4CIDRs, "bird_v4.conf")
    nchnroutes.OutputIPv6BirdConfig(ipv6CIDRs, "bird_v6.conf")
}
```

### 验证生成的配置

```go
package main

import (
    "log"
    "github.com/ipipdotnet/ipdb-go/nchnroutes"
)

func main() {
    // 创建验证器
    validator, err := nchnroutes.NewIPValidator("city.free.ipdb", 5)
    if err != nil {
        log.Fatal(err)
    }

    // 提取并验证CIDR
    cidrs, err := validator.ExtractCIDRsFromBirdConfig("bird_v4.conf")
    if err != nil {
        log.Fatal(err)
    }

    validator.ValidateCIDRs(cidrs)
    validator.GenerateReport()
}
```

## 模块依赖

此包依赖于：
- `github.com/ipipdotnet/ipdb-go` - IPDB Go SDK

## 命令行工具

您可以基于这些功能创建命令行工具：

1. **生成工具** - 使用提取器、过滤器、合并器和输出器生成Bird配置
2. **验证工具** - 使用验证器检查生成的配置文件

## 注意事项

1. 过滤功能会排除中国大陆IP地址，但保留香港、澳门、台湾的IP
2. 并行过滤适用于大量IP范围，小数据集使用串行过滤即可
3. CIDR合并功能会尝试合并相邻的网络段以减少配置文件大小
4. 验证器会采样检查CIDR中的IP地址，默认每个CIDR采样5个IP 