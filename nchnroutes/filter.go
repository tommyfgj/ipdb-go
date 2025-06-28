package nchnroutes

import (
	"net"
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

// FilterRanges 过滤IP范围并收集统计信息
func FilterRanges(ranges []IPRange) ([]IPRange, FilterStats) {
	var filtered []IPRange
	stats := FilterStats{TotalRanges: len(ranges)}

	for _, r := range ranges {
		// 检查中国大陆
		if IsMainlandChina(r.Info) {
			stats.ChinaFiltered++
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

	return filtered, stats
}

// FilterRangesParallel 并行过滤IP范围
func FilterRangesParallel(ranges []IPRange) ([]IPRange, FilterStats) {
	if len(ranges) == 0 {
		return ranges, FilterStats{TotalRanges: 0}
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
		filtered []IPRange
		stats    FilterStats
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
			filtered, stats := FilterRanges(chunk)
			// 重置TotalRanges，因为我们会在最后重新计算
			stats.TotalRanges = len(chunk)
			resultChan <- result{filtered: filtered, stats: stats}
		}(ranges[start:end])
	}

	// 等待所有workers完成
	go func() {
		wg.Wait()
		close(resultChan)
	}()

	// 收集结果
	var allFiltered []IPRange
	var totalStats FilterStats
	totalStats.TotalRanges = len(ranges)

	for res := range resultChan {
		allFiltered = append(allFiltered, res.filtered...)
		totalStats.ChinaFiltered += res.stats.ChinaFiltered
		totalStats.PrivateFiltered += res.stats.PrivateFiltered
		totalStats.HongKongKept += res.stats.HongKongKept
		totalStats.MacaoKept += res.stats.MacaoKept
		totalStats.TaiwanKept += res.stats.TaiwanKept
		totalStats.OtherKept += res.stats.OtherKept
	}

	return allFiltered, totalStats
}
