package nchnroutes

import (
	"fmt"
	"net"
	"os"
	"runtime"
	"strings"
	"sync"
)

// FilterStats 过滤统计信息
type FilterStats struct {
	TotalRanges     int
	ChinaFiltered   int
	PrivateFiltered int
	HongKongKept    int
	MacaoKept       int
	TaiwanKept      int
	OtherKept       int
	ChinaCIDRsSaved int // 保存的中国大陆CIDR数量
}

// IsMainlandChina 检查是否为中国大陆IP（排除港澳台）
func IsMainlandChina(info []string) bool {
	if len(info) == 0 {
		return false
	}

	countryName := info[0]
	regionName := ""
	if len(info) > 1 {
		regionName = info[1]
	}

	// 中国大陆
	if countryName == "中国" || countryName == "CN" || countryName == "China" {
		// 排除港澳台
		if strings.Contains(regionName, "香港") || strings.Contains(regionName, "Hong Kong") ||
			strings.Contains(regionName, "澳门") || strings.Contains(regionName, "Macao") || strings.Contains(regionName, "Macau") ||
			strings.Contains(regionName, "台湾") || strings.Contains(regionName, "Taiwan") {
			return false
		}
		return true
	}

	return false
}

// IsPrivateOrReserved 检查是否为私有/保留地址
func IsPrivateOrReserved(startIP, endIP net.IP) bool {
	// IPv4私有地址
	if startIP.To4() != nil {
		// 10.0.0.0/8
		if startIP[0] == 10 {
			return true
		}
		// 172.16.0.0/12
		if startIP[0] == 172 && startIP[1] >= 16 && startIP[1] <= 31 {
			return true
		}
		// 192.168.0.0/16
		if startIP[0] == 192 && startIP[1] == 168 {
			return true
		}
		// 127.0.0.0/8 (回环)
		if startIP[0] == 127 {
			return true
		}
		// 169.254.0.0/16 (链路本地)
		if startIP[0] == 169 && startIP[1] == 254 {
			return true
		}
		// 224.0.0.0/4 (组播)
		if startIP[0] >= 224 && startIP[0] <= 239 {
			return true
		}
		// 240.0.0.0/4 (保留)
		if startIP[0] >= 240 {
			return true
		}
		// 0.0.0.0/8 (保留)
		if startIP[0] == 0 {
			return true
		}
	} else {
		// IPv6私有/保留地址
		// ::1/128 (回环)
		if startIP.IsLoopback() {
			return true
		}
		// fe80::/10 (链路本地)
		if startIP[0] == 0xfe && (startIP[1]&0xc0) == 0x80 {
			return true
		}
		// fc00::/7 (唯一本地)
		if (startIP[0] & 0xfe) == 0xfc {
			return true
		}
		// ff00::/8 (组播)
		if startIP[0] == 0xff {
			return true
		}
		// ::/128 (未指定)
		if startIP.IsUnspecified() {
			return true
		}
	}

	return false
}

// isHongKong 检查是否为香港
func isHongKong(info []string) bool {
	if len(info) == 0 {
		return false
	}

	countryName := info[0]
	regionName := ""
	if len(info) > 1 {
		regionName = info[1]
	}

	return (countryName == "中国" || countryName == "CN" || countryName == "China") &&
		(strings.Contains(regionName, "香港") || strings.Contains(regionName, "Hong Kong"))
}

// isMacao 检查是否为澳门
func isMacao(info []string) bool {
	if len(info) == 0 {
		return false
	}

	countryName := info[0]
	regionName := ""
	if len(info) > 1 {
		regionName = info[1]
	}

	return (countryName == "中国" || countryName == "CN" || countryName == "China") &&
		(strings.Contains(regionName, "澳门") || strings.Contains(regionName, "Macao") || strings.Contains(regionName, "Macau"))
}

// isTaiwan 检查是否为台湾
func isTaiwan(info []string) bool {
	if len(info) == 0 {
		return false
	}

	countryName := info[0]
	regionName := ""
	if len(info) > 1 {
		regionName = info[1]
	}

	return (countryName == "中国" || countryName == "CN" || countryName == "China") &&
		(strings.Contains(regionName, "台湾") || strings.Contains(regionName, "Taiwan"))
}

// FilterRanges 过滤IP范围并收集统计信息，同时收集中国大陆IP段
func FilterRanges(ranges []IPRange) ([]IPRange, []IPRange, FilterStats) {
	var filtered []IPRange
	var chinaRanges []IPRange // 收集中国大陆IP段
	stats := FilterStats{TotalRanges: len(ranges)}

	for _, r := range ranges {
		// 检查中国大陆
		if IsMainlandChina(r.Info) {
			stats.ChinaFiltered++
			// 排除私有/保留地址后再添加到中国大陆列表
			if !IsPrivateOrReserved(r.StartIP, r.EndIP) {
				chinaRanges = append(chinaRanges, r)
			}
			continue
		}

		// 检查港澳台
		if isHongKong(r.Info) {
			stats.HongKongKept++
		} else if isMacao(r.Info) {
			stats.MacaoKept++
		} else if isTaiwan(r.Info) {
			stats.TaiwanKept++
		} else {
			stats.OtherKept++
		}

		// 排除私有/保留地址
		if IsPrivateOrReserved(r.StartIP, r.EndIP) {
			stats.PrivateFiltered++
			continue
		}

		filtered = append(filtered, r)
	}

	stats.ChinaCIDRsSaved = len(chinaRanges)
	return filtered, chinaRanges, stats
}

// FilterRangesParallel 并行过滤IP范围
func FilterRangesParallel(ranges []IPRange) ([]IPRange, []IPRange, FilterStats) {
	if len(ranges) == 0 {
		return ranges, []IPRange{}, FilterStats{TotalRanges: 0}
	}

	// 获取CPU核心数，设置并发数
	numWorkers := runtime.NumCPU()
	if numWorkers > len(ranges) {
		numWorkers = len(ranges)
	}

	// 计算每个worker处理的数据量
	chunkSize := len(ranges) / numWorkers
	if chunkSize == 0 {
		chunkSize = 1
	}

	// 创建channels和WaitGroup
	type result struct {
		filtered    []IPRange
		chinaRanges []IPRange
		stats       FilterStats
	}

	resultChan := make(chan result, numWorkers)
	var wg sync.WaitGroup

	// 启动workers
	for i := 0; i < numWorkers; i++ {
		start := i * chunkSize
		end := start + chunkSize
		if i == numWorkers-1 {
			end = len(ranges) // 最后一个worker处理剩余的所有数据
		}

		wg.Add(1)
		go func(chunk []IPRange) {
			defer wg.Done()
			filtered, chinaRanges, stats := FilterRanges(chunk)
			// 重置TotalRanges，因为我们会在最后重新计算
			stats.TotalRanges = len(chunk)
			resultChan <- result{filtered: filtered, chinaRanges: chinaRanges, stats: stats}
		}(ranges[start:end])
	}

	// 等待所有workers完成
	go func() {
		wg.Wait()
		close(resultChan)
	}()

	// 收集结果
	var allFiltered []IPRange
	var allChinaRanges []IPRange
	var totalStats FilterStats
	totalStats.TotalRanges = len(ranges)

	for res := range resultChan {
		allFiltered = append(allFiltered, res.filtered...)
		allChinaRanges = append(allChinaRanges, res.chinaRanges...)
		totalStats.ChinaFiltered += res.stats.ChinaFiltered
		totalStats.PrivateFiltered += res.stats.PrivateFiltered
		totalStats.HongKongKept += res.stats.HongKongKept
		totalStats.MacaoKept += res.stats.MacaoKept
		totalStats.TaiwanKept += res.stats.TaiwanKept
		totalStats.OtherKept += res.stats.OtherKept
		totalStats.ChinaCIDRsSaved += res.stats.ChinaCIDRsSaved
	}

	return allFiltered, allChinaRanges, totalStats
}

// SaveChinaRoutes 保存中国大陆IP段到文件
func SaveChinaRoutes(ipv4ChinaRanges, ipv6ChinaRanges []IPRange, outputDir string) error {
	// 转换为CIDR并合并
	ipv4CIDRs := RangesToCIDRs(ipv4ChinaRanges)
	ipv6CIDRs := RangesToCIDRs(ipv6ChinaRanges)

	mergedIPv4 := MergeCIDRs(ipv4CIDRs)
	mergedIPv6 := MergeCIDRs(ipv6CIDRs)

	// 保存IPv4中国路由
	if len(mergedIPv4) > 0 {
		ipv4File := fmt.Sprintf("%s/chnroute-ipv4.txt", outputDir)
		if err := saveRouteFile(mergedIPv4, ipv4File, "IPv4"); err != nil {
			return fmt.Errorf("保存IPv4中国路由失败: %v", err)
		}
		fmt.Printf("IPv4中国路由已保存到: %s (共%d个网段)\n", ipv4File, len(mergedIPv4))
	}

	// 保存IPv6中国路由
	if len(mergedIPv6) > 0 {
		ipv6File := fmt.Sprintf("%s/chnroute-ipv6.txt", outputDir)
		if err := saveRouteFile(mergedIPv6, ipv6File, "IPv6"); err != nil {
			return fmt.Errorf("保存IPv6中国路由失败: %v", err)
		}
		fmt.Printf("IPv6中国路由已保存到: %s (共%d个网段)\n", ipv6File, len(mergedIPv6))
	}

	return nil
}

// saveRouteFile 保存路由文件
func saveRouteFile(cidrs []CIDR, filename, ipVersion string) error {
	var content strings.Builder

	content.WriteString(fmt.Sprintf("# 中国大陆%s网段列表\n", ipVersion))
	content.WriteString("# 此文件包含所有中国大陆的IP段（已排除私有地址并合并相邻网段）\n")
	content.WriteString(fmt.Sprintf("# 共%d个网段\n\n", len(cidrs)))

	for _, cidr := range cidrs {
		content.WriteString(cidr.Network.String() + "\n")
	}

	return os.WriteFile(filename, []byte(content.String()), 0644)
}
