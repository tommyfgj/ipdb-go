package main

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"sort"
	"strings"
)

// CoverageRange 表示一个IPv4地址范围用于覆盖检查
type CoverageRange struct {
	Start uint32
	End   uint32
	CIDR  string
	Type  string // "china", "foreign", "reserved"
}

// CoverageRangeList 实现排序接口
type CoverageRangeList []CoverageRange

func (r CoverageRangeList) Len() int           { return len(r) }
func (r CoverageRangeList) Swap(i, j int)      { r[i], r[j] = r[j], r[i] }
func (r CoverageRangeList) Less(i, j int) bool { return r[i].Start < r[j].Start }

// convertIPToUint32 将IP地址转换为uint32
func convertIPToUint32(ip net.IP) uint32 {
	ip = ip.To4()
	if ip == nil {
		return 0
	}
	return uint32(ip[0])<<24 + uint32(ip[1])<<16 + uint32(ip[2])<<8 + uint32(ip[3])
}

// convertUint32ToIP 将uint32转换为IP地址
func convertUint32ToIP(ip uint32) net.IP {
	return net.IPv4(
		byte(ip>>24),
		byte(ip>>16),
		byte(ip>>8),
		byte(ip),
	)
}

// convertCIDRToRange 将CIDR转换为CoverageRange
func convertCIDRToRange(cidr, rangeType string) (*CoverageRange, error) {
	_, ipNet, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, err
	}

	// 确保是IPv4
	if ipNet.IP.To4() == nil {
		return nil, fmt.Errorf("不是IPv4地址: %s", cidr)
	}

	start := convertIPToUint32(ipNet.IP)
	ones, bits := ipNet.Mask.Size()
	if bits != 32 {
		return nil, fmt.Errorf("无效的IPv4掩码")
	}

	// 计算网络中的地址数量
	hostBits := 32 - ones
	numAddresses := uint32(1) << hostBits
	end := start + numAddresses - 1

	return &CoverageRange{
		Start: start,
		End:   end,
		CIDR:  cidr,
		Type:  rangeType,
	}, nil
}

// 解析chnroute-ipv4.txt文件
func parseChinaRouteFile(filename string) ([]CoverageRange, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var ranges []CoverageRange
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		r, err := convertCIDRToRange(line, "china")
		if err != nil {
			return nil, fmt.Errorf("解析中国路由失败 %s: %v", line, err)
		}
		ranges = append(ranges, *r)
	}

	return ranges, scanner.Err()
}

// 解析bird_v4.conf文件
func parseBirdRouteFile(filename string) ([]CoverageRange, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var ranges []CoverageRange
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// 解析格式: route x.x.x.x/xx via "wg0";
		if strings.HasPrefix(line, "route ") {
			parts := strings.Fields(line)
			if len(parts) >= 2 {
				cidr := parts[1]
				r, err := convertCIDRToRange(cidr, "foreign")
				if err != nil {
					return nil, fmt.Errorf("解析bird路由失败 %s: %v", line, err)
				}
				ranges = append(ranges, *r)
			}
		}
	}

	return ranges, scanner.Err()
}

// 获取保留地址段
func getIPv4ReservedRanges() []CoverageRange {
	reservedCIDRs := []string{
		"0.0.0.0/8",      // 保留
		"10.0.0.0/8",     // 私有
		"127.0.0.0/8",    // 回环
		"169.254.0.0/16", // 链路本地
		"172.16.0.0/12",  // 私有
		"192.168.0.0/16", // 私有
		"224.0.0.0/4",    // 组播
		"240.0.0.0/4",    // 保留
	}

	var ranges []CoverageRange
	for _, cidr := range reservedCIDRs {
		r, err := convertCIDRToRange(cidr, "reserved")
		if err != nil {
			continue // 跳过无效的CIDR
		}
		ranges = append(ranges, *r)
	}

	return ranges
}

// 合并重叠的范围
func mergeCoverageRanges(ranges []CoverageRange) []CoverageRange {
	if len(ranges) == 0 {
		return ranges
	}

	// 按起始地址排序
	sort.Sort(CoverageRangeList(ranges))

	var merged []CoverageRange
	current := ranges[0]

	for i := 1; i < len(ranges); i++ {
		next := ranges[i]

		// 如果当前范围和下一个范围重叠或相邻
		if current.End+1 >= next.Start {
			// 合并范围
			if next.End > current.End {
				current.End = next.End
			}
			// 更新CIDR信息
			current.CIDR = fmt.Sprintf("%s+%s", current.CIDR, next.CIDR)
			if current.Type != next.Type {
				current.Type = fmt.Sprintf("%s+%s", current.Type, next.Type)
			}
		} else {
			// 不重叠，添加当前范围到结果
			merged = append(merged, current)
			current = next
		}
	}

	// 添加最后一个范围
	merged = append(merged, current)

	return merged
}

// 查找IPv4空间中的gap
func findIPv4Gaps(ranges []CoverageRange) []CoverageRange {
	if len(ranges) == 0 {
		// 如果没有任何范围，整个IPv4空间都是gap
		return []CoverageRange{{
			Start: 0,
			End:   0xFFFFFFFF,
			CIDR:  "0.0.0.0/0",
			Type:  "gap",
		}}
	}

	// 合并重叠的范围
	merged := mergeCoverageRanges(ranges)

	var gaps []CoverageRange

	// 检查第一个范围之前是否有gap
	if merged[0].Start > 0 {
		gaps = append(gaps, CoverageRange{
			Start: 0,
			End:   merged[0].Start - 1,
			CIDR:  fmt.Sprintf("%s-%s", convertUint32ToIP(0).String(), convertUint32ToIP(merged[0].Start-1).String()),
			Type:  "gap",
		})
	}

	// 检查范围之间的gap
	for i := 0; i < len(merged)-1; i++ {
		if merged[i].End+1 < merged[i+1].Start {
			gaps = append(gaps, CoverageRange{
				Start: merged[i].End + 1,
				End:   merged[i+1].Start - 1,
				CIDR:  fmt.Sprintf("%s-%s", convertUint32ToIP(merged[i].End+1).String(), convertUint32ToIP(merged[i+1].Start-1).String()),
				Type:  "gap",
			})
		}
	}

	// 检查最后一个范围之后是否有gap
	lastRange := merged[len(merged)-1]
	if lastRange.End < 0xFFFFFFFF {
		gaps = append(gaps, CoverageRange{
			Start: lastRange.End + 1,
			End:   0xFFFFFFFF,
			CIDR:  fmt.Sprintf("%s-%s", convertUint32ToIP(lastRange.End+1).String(), convertUint32ToIP(0xFFFFFFFF).String()),
			Type:  "gap",
		})
	}

	return gaps
}

// 计算范围中的IP地址数量
func countCoverageIPs(ranges []CoverageRange) uint64 {
	var total uint64
	for _, r := range ranges {
		total += uint64(r.End - r.Start + 1)
	}
	return total
}

func main() {
	fmt.Println("开始检查IPv4空间覆盖情况...")

	// 解析中国路由文件
	chinaRanges, err := parseChinaRouteFile("../../output/chnroute-ipv4.txt")
	if err != nil {
		fmt.Printf("解析中国路由文件失败: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("中国大陆路由段数: %d\n", len(chinaRanges))

	// 解析bird路由文件
	foreignRanges, err := parseBirdRouteFile("../../output/bird_v4.conf")
	if err != nil {
		fmt.Printf("解析bird路由文件失败: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("外国路由段数: %d\n", len(foreignRanges))

	// 获取保留地址段
	reservedRanges := getIPv4ReservedRanges()
	fmt.Printf("保留地址段数: %d\n", len(reservedRanges))

	// 合并所有范围
	allRanges := make([]CoverageRange, 0, len(chinaRanges)+len(foreignRanges)+len(reservedRanges))
	allRanges = append(allRanges, chinaRanges...)
	allRanges = append(allRanges, foreignRanges...)
	allRanges = append(allRanges, reservedRanges...)

	fmt.Printf("总路由段数: %d\n", len(allRanges))

	// 查找gap
	gaps := findIPv4Gaps(allRanges)

	// 计算覆盖统计
	totalIPv4 := uint64(0x100000000) // 2^32
	chinaIPs := countCoverageIPs(chinaRanges)
	foreignIPs := countCoverageIPs(foreignRanges)
	reservedIPs := countCoverageIPs(reservedRanges)
	gapIPs := countCoverageIPs(gaps)

	fmt.Printf("\n=== IPv4空间覆盖统计 ===\n")
	fmt.Printf("IPv4总地址空间: %d (2^32)\n", totalIPv4)
	fmt.Printf("中国大陆地址: %d (%.2f%%)\n", chinaIPs, float64(chinaIPs)*100/float64(totalIPv4))
	fmt.Printf("外国地址: %d (%.2f%%)\n", foreignIPs, float64(foreignIPs)*100/float64(totalIPv4))
	fmt.Printf("保留地址: %d (%.2f%%)\n", reservedIPs, float64(reservedIPs)*100/float64(totalIPv4))
	fmt.Printf("Gap地址: %d (%.2f%%)\n", gapIPs, float64(gapIPs)*100/float64(totalIPv4))

	// 验证覆盖度
	coveredIPs := chinaIPs + foreignIPs + reservedIPs + gapIPs
	fmt.Printf("总计算地址: %d\n", coveredIPs)

	if len(gaps) == 0 {
		fmt.Println("\n✅ 完全覆盖IPv4空间，没有gap!")
	} else {
		fmt.Printf("\n❌ 发现%d个gap:\n", len(gaps))
		for i, gap := range gaps {
			fmt.Printf("Gap %d: %s (大小: %d个地址)\n", i+1, gap.CIDR, gap.End-gap.Start+1)

			// 如果gap很小，显示具体的CIDR
			if gap.End-gap.Start+1 <= 256 {
				gapStart := convertUint32ToIP(gap.Start)
				gapEnd := convertUint32ToIP(gap.End)
				fmt.Printf("  具体范围: %s - %s\n", gapStart.String(), gapEnd.String())
			}
		}
	}

	// 如果有gap，以错误码退出
	if len(gaps) > 0 {
		fmt.Printf("\n发现%d个IPv4空间gap，总共%d个未覆盖地址\n", len(gaps), gapIPs)
		os.Exit(1)
	}
}
