package nchnroutes

import (
	"fmt"
	"math/big"
	"net"
	"sort"
)

// CIDR represents a network range for merging
type CIDR struct {
	Network *net.IPNet
	StartIP net.IP
	EndIP   net.IP
}

// BlockingRange 阻塞IP段结构，用于快速查找
type BlockingRange struct {
	StartIP net.IP
	EndIP   net.IP
	Type    string // "china" or "private"
}

// PreprocessedRanges 预处理后的阻塞IP段
type PreprocessedRanges struct {
	IPv4Blocking []BlockingRange
	IPv6Blocking []BlockingRange
}

// IPRangeDecimal 用于高效处理IP范围的十进制表示
type IPRangeDecimal struct {
	Start  *big.Int
	End    *big.Int
	IsIPv4 bool
}

// SmartMergeNonChinaCIDRs 高效合并非中国大陆CIDR，严格按照Rust实现
func SmartMergeNonChinaCIDRs(allIPv4, allIPv6 []IPRange, nonChinaIPv4, nonChinaIPv6 []IPRange) ([]CIDR, []CIDR) {
	fmt.Println("正在进行高效CIDR聚合...")

	// 使用严格按照Rust实现的算法
	mergedIPv4 := rustStyleAggregateAndNormalize(nonChinaIPv4, true)
	mergedIPv6 := rustStyleAggregateAndNormalize(nonChinaIPv6, false)

	fmt.Printf("高效聚合完成: %d个IPv4段, %d个IPv6段\n", len(mergedIPv4), len(mergedIPv6))
	return mergedIPv4, mergedIPv6
}

// rustStyleAggregateAndNormalize 严格按照Rust实现的聚合和标准化算法
func rustStyleAggregateAndNormalize(ranges []IPRange, isIPv4 bool) []CIDR {
	if len(ranges) == 0 {
		return []CIDR{}
	}

	// 步骤1：聚合 - 严格按照Rust的aggregated函数
	aggregated := rustStyleAggregated(ranges, isIPv4)

	// 步骤2：标准化 - 严格按照Rust的normalized函数
	normalized := rustStyleNormalized(aggregated, isIPv4)

	return normalized
}

// rustStyleAggregated 严格按照Rust的aggregated函数实现
func rustStyleAggregated(ranges []IPRange, isIPv4 bool) []DecimalRange {
	if len(ranges) == 0 {
		return []DecimalRange{}
	}

	// 排序ranges（按起始地址）
	sort.Slice(ranges, func(i, j int) bool {
		return compareIPs(ranges[i].StartIP, ranges[j].StartIP) < 0
	})

	// 转换为十进制对 (first_address_as_decimal, last_address_as_decimal)
	var decimalPairs []DecimalRange
	for _, r := range ranges {
		first := ipToDecimal(r.StartIP)
		last := ipToDecimal(r.EndIP)
		if first != nil && last != nil {
			decimalPairs = append(decimalPairs, DecimalRange{
				First:  first,
				Last:   last,
				IsIPv4: isIPv4,
			})
		}
	}

	if len(decimalPairs) == 0 {
		return []DecimalRange{}
	}

	var aggregatedRanges []DecimalRange
	lastRange := decimalPairs[0]

	for i := 1; i < len(decimalPairs); i++ {
		currentRange := decimalPairs[i]

		// Rust逻辑: if max(range.0, 1) - 1 <= last_range.1
		maxFirst := new(big.Int).Set(currentRange.First)
		one := big.NewInt(1)
		if maxFirst.Cmp(one) < 0 {
			maxFirst = one
		}

		condition := new(big.Int).Sub(maxFirst, one)
		if condition.Cmp(lastRange.Last) <= 0 {
			// 可以合并: last_range = (last_range.0, max(range.1, last_range.1))
			if currentRange.Last.Cmp(lastRange.Last) > 0 {
				lastRange.Last = new(big.Int).Set(currentRange.Last)
			}
		} else {
			// 不能合并，保存当前range，开始新的range
			aggregatedRanges = append(aggregatedRanges, lastRange)
			lastRange = currentRange
		}
	}

	// 添加最后一个range
	aggregatedRanges = append(aggregatedRanges, lastRange)
	return aggregatedRanges
}

// rustStyleNormalized 严格按照Rust的normalized函数实现
func rustStyleNormalized(ranges []DecimalRange, isIPv4 bool) []CIDR {
	var normalizedRanges []CIDR

	var maxBits int
	if isIPv4 {
		maxBits = 32
	} else {
		maxBits = 128
	}

	for _, r := range ranges {
		first := new(big.Int).Set(r.First)
		length := new(big.Int).Sub(r.Last, r.First)
		length.Add(length, big.NewInt(1)) // length = last - first + 1

		// Rust逻辑: if first == 0 && length == 0 { push full range; break }
		if first.Cmp(big.NewInt(0)) == 0 && length.Cmp(big.NewInt(0)) == 0 {
			// 创建全范围CIDR
			var network *net.IPNet
			if isIPv4 {
				network = &net.IPNet{IP: net.IPv4zero, Mask: net.CIDRMask(0, 32)}
			} else {
				network = &net.IPNet{IP: net.IPv6zero, Mask: net.CIDRMask(0, 128)}
			}
			normalizedRanges = append(normalizedRanges, CIDR{
				Network: network,
				StartIP: network.IP,
				EndIP:   calculateNetworkEndIP(network),
			})
			break
		}

		// Rust的主循环逻辑
		for length.Cmp(big.NewInt(0)) > 0 {
			// 计算 b = 2^min(length.log2(), first.trailing_zeros())
			lengthLog2 := bigIntLog2(length)
			var firstTrailingZeros int
			if first.Cmp(big.NewInt(0)) == 0 {
				firstTrailingZeros = maxBits
			} else {
				firstTrailingZeros = bigIntTrailingZeros(first)
			}

			minPower := lengthLog2
			if firstTrailingZeros < minPower {
				minPower = firstTrailingZeros
			}

			// b = 2^minPower
			b := new(big.Int).Lsh(big.NewInt(1), uint(minPower))

			// 创建CIDR: (first, first + b - 1)
			rangeEnd := new(big.Int).Add(first, b)
			rangeEnd.Sub(rangeEnd, big.NewInt(1))

			// 转换为CIDR
			prefixLen := maxBits - minPower

			cidr := createCIDRFromDecimalRange(first, prefixLen, isIPv4)
			if cidr != nil {
				normalizedRanges = append(normalizedRanges, *cidr)
			}

			// 更新循环变量: length -= b, first += b
			length.Sub(length, b)
			first.Add(first, b)
		}
	}

	return normalizedRanges
}

// DecimalRange 十进制IP范围表示
type DecimalRange struct {
	First  *big.Int
	Last   *big.Int
	IsIPv4 bool
}

// bigIntLog2 计算大整数的log2值
func bigIntLog2(n *big.Int) int {
	if n.Cmp(big.NewInt(0)) <= 0 {
		return 0
	}
	return n.BitLen() - 1
}

// bigIntTrailingZeros 计算大整数的尾随零个数
func bigIntTrailingZeros(n *big.Int) int {
	if n.Cmp(big.NewInt(0)) == 0 {
		return 0
	}

	count := 0
	temp := new(big.Int).Set(n)
	for temp.Bit(count) == 0 {
		count++
		if count >= 128 { // 防止无限循环
			break
		}
	}
	return count
}

// createCIDRFromDecimalRange 从十进制范围创建CIDR
func createCIDRFromDecimalRange(start *big.Int, prefixLen int, isIPv4 bool) *CIDR {
	startIP := decimalToIP(start, isIPv4)
	if startIP == nil {
		return nil
	}

	var bits int
	if isIPv4 {
		bits = 32
	} else {
		bits = 128
	}

	// 创建网络
	mask := net.CIDRMask(prefixLen, bits)
	network := &net.IPNet{IP: startIP.Mask(mask), Mask: mask}

	return &CIDR{
		Network: network,
		StartIP: network.IP,
		EndIP:   calculateNetworkEndIP(network),
	}
}

// ipToDecimal 将IP地址转换为大整数
func ipToDecimal(ip net.IP) *big.Int {
	if ip == nil {
		return nil
	}

	// 区分IPv4和IPv6，避免错误的转换
	if ipv4 := ip.To4(); ipv4 != nil {
		// IPv4地址，使用4字节
		return new(big.Int).SetBytes(ipv4)
	} else {
		// IPv6地址，使用16字节
		ip = ip.To16()
		if ip == nil {
			return nil
		}
		return new(big.Int).SetBytes(ip)
	}
}

// decimalToIP 将大整数转换为IP地址
func decimalToIP(decimal *big.Int, isIPv4 bool) net.IP {
	bytes := decimal.Bytes()

	if isIPv4 {
		ip := make(net.IP, 4)
		// 安全地复制字节，避免越界
		if len(bytes) <= 4 {
			copy(ip[4-len(bytes):], bytes)
		} else {
			// 如果字节太多，只取最后4个字节
			copy(ip, bytes[len(bytes)-4:])
		}
		return ip
	} else {
		ip := make(net.IP, 16)
		// 安全地复制字节，避免越界
		if len(bytes) <= 16 {
			copy(ip[16-len(bytes):], bytes)
		} else {
			// 如果字节太多，只取最后16个字节
			copy(ip, bytes[len(bytes)-16:])
		}
		return ip
	}
}

// calculateNetworkEndIP 计算网络的结束IP
func calculateNetworkEndIP(network *net.IPNet) net.IP {
	ip := make(net.IP, len(network.IP))
	copy(ip, network.IP)

	for i := len(ip) - 1; i >= 0; i-- {
		ip[i] |= ^network.Mask[i]
	}
	return ip
}

// MergeCIDRs 合并相邻的CIDR（保留原有功能以兼容其他代码）
func MergeCIDRs(cidrs []CIDR) []CIDR {
	if len(cidrs) == 0 {
		return cidrs
	}

	// 转换为十进制进行处理
	var ranges []DecimalRange
	for _, cidr := range cidrs {
		start := ipToDecimal(cidr.StartIP)
		end := ipToDecimal(cidr.EndIP)
		if start != nil && end != nil {
			ranges = append(ranges, DecimalRange{
				First:  start,
				Last:   end,
				IsIPv4: isIPv4(cidr.StartIP),
			})
		}
	}

	// 使用简单的聚合算法（不需要转换为IPRange）
	aggregated := simpleAggregateDecimalRanges(ranges)

	// 使用Rust风格的标准化算法将聚合后的范围转换为最优CIDR列表
	if len(aggregated) == 0 {
		return []CIDR{}
	}

	isIPv4 := aggregated[0].IsIPv4
	normalizedCIDRs := rustStyleNormalized(aggregated, isIPv4)

	return normalizedCIDRs
}

// simpleAggregateDecimalRanges 简单的十进制范围聚合
func simpleAggregateDecimalRanges(ranges []DecimalRange) []DecimalRange {
	if len(ranges) == 0 {
		return ranges
	}

	// 排序
	sort.Slice(ranges, func(i, j int) bool {
		return ranges[i].First.Cmp(ranges[j].First) < 0
	})

	var aggregated []DecimalRange
	current := ranges[0]

	for i := 1; i < len(ranges); i++ {
		next := ranges[i]

		// 简单的相邻性检查: next.first <= current.last + 1
		nextFirst := new(big.Int).Set(next.First)
		currentLastPlusOne := new(big.Int).Add(current.Last, big.NewInt(1))

		if nextFirst.Cmp(currentLastPlusOne) <= 0 {
			// 可以合并
			if next.Last.Cmp(current.Last) > 0 {
				current.Last = new(big.Int).Set(next.Last)
			}
		} else {
			// 不能合并
			aggregated = append(aggregated, current)
			current = next
		}
	}

	aggregated = append(aggregated, current)
	return aggregated
}

// createSimpleCIDR 创建覆盖指定范围的简单CIDR
func createSimpleCIDR(startIP, endIP net.IP, isIPv4 bool) *CIDR {
	var bits int
	if isIPv4 {
		bits = 32
	} else {
		bits = 128
	}

	// 找到能包含整个范围的最小前缀
	for prefix := 0; prefix <= bits; prefix++ {
		mask := net.CIDRMask(prefix, bits)
		network := &net.IPNet{IP: startIP.Mask(mask), Mask: mask}
		networkEnd := calculateNetworkEndIP(network)

		if network.Contains(startIP) && compareIPs(networkEnd, endIP) >= 0 {
			return &CIDR{
				Network: network,
				StartIP: startIP,
				EndIP:   endIP,
			}
		}
	}

	// 如果找不到合适的单个CIDR，返回nil（调用方需要进一步处理）
	return nil
}

// isIPv4 检查IP地址是否为IPv4
func isIPv4(ip net.IP) bool {
	return ip.To4() != nil
}

// compareIPs 比较两个IP地址
func compareIPs(ip1, ip2 net.IP) int {
	// 确保两个IP长度相同
	if len(ip1) != len(ip2) {
		ip1 = ip1.To16()
		ip2 = ip2.To16()
	}

	for i := 0; i < len(ip1); i++ {
		if ip1[i] < ip2[i] {
			return -1
		} else if ip1[i] > ip2[i] {
			return 1
		}
	}
	return 0
}

// 保留原有的函数以兼容其他代码
func RangesToCIDRs(ranges []IPRange) []CIDR {
	// 对于简单的转换，使用直接的方法，不进行复杂的聚合
	var cidrs []CIDR

	for _, r := range ranges {
		_, network, err := net.ParseCIDR(r.CIDR)
		if err == nil {
			cidrs = append(cidrs, CIDR{
				Network: network,
				StartIP: r.StartIP,
				EndIP:   r.EndIP,
			})
		}
	}

	return cidrs
}

// practicalMergeWithSafetyCheck 实用的合并策略：优先合并相邻网段，最后验证安全性
func practicalMergeWithSafetyCheck(nonChinaRanges []IPRange, blockingRanges []IPRange, isIPv4 bool) []CIDR {
	if len(nonChinaRanges) == 0 {
		return []CIDR{}
	}

	// 先转换为CIDR并进行传统的相邻合并
	var cidrs []CIDR
	for _, r := range nonChinaRanges {
		_, network, err := net.ParseCIDR(r.CIDR)
		if err == nil {
			cidrs = append(cidrs, CIDR{
				Network: network,
				StartIP: r.StartIP,
				EndIP:   r.EndIP,
			})
		}
	}

	// 使用传统的相邻合并
	mergedCIDRs := MergeCIDRs(cidrs)

	// 验证合并结果，移除会覆盖阻塞网段的CIDR
	var safeCIDRs []CIDR
	for _, cidr := range mergedCIDRs {
		if isSafeCIDR(cidr, blockingRanges, isIPv4) {
			safeCIDRs = append(safeCIDRs, cidr)
		} else {
			// 不安全的CIDR，拆分回原始范围
			splitCIDRs := splitUnsafeCIDR(cidr, blockingRanges, isIPv4)
			safeCIDRs = append(safeCIDRs, splitCIDRs...)
		}
	}

	return safeCIDRs
}

// isSafeCIDR 检查CIDR是否安全（不会覆盖阻塞网段）
func isSafeCIDR(cidr CIDR, blockingRanges []IPRange, isIPv4 bool) bool {
	// 检查前缀长度限制
	if isIPv4 {
		prefixLen, _ := cidr.Network.Mask.Size()
		if prefixLen < 8 { // 不允许大于/8的IPv4网段
			return false
		}
	} else {
		prefixLen, _ := cidr.Network.Mask.Size()
		if prefixLen < 32 { // 不允许大于/32的IPv6网段
			return false
		}
	}

	// 检查是否与阻塞网段重叠
	for _, blocking := range blockingRanges {
		if compareIPs(cidr.StartIP, blocking.EndIP) <= 0 && compareIPs(blocking.StartIP, cidr.EndIP) <= 0 {
			return false // 与阻塞网段重叠，不安全
		}
	}

	return true
}

// splitUnsafeCIDR 将不安全的CIDR拆分成安全的小段
func splitUnsafeCIDR(cidr CIDR, blockingRanges []IPRange, isIPv4 bool) []CIDR {
	// 简化版：如果CIDR不安全，就拆分成/24（IPv4）或/64（IPv6）
	var result []CIDR

	if isIPv4 {
		// 拆分成/24网段
		current := cidr.StartIP
		for compareIPs(current, cidr.EndIP) <= 0 {
			// 创建/24网段
			_, subnet, err := net.ParseCIDR(fmt.Sprintf("%s/24", current.String()))
			if err != nil {
				break
			}

			// 计算/24网段的结束IP
			endIP := make(net.IP, 4)
			copy(endIP, current)
			endIP[3] = 255

			if compareIPs(endIP, cidr.EndIP) > 0 {
				endIP = cidr.EndIP
			}

			newCIDR := CIDR{
				Network: subnet,
				StartIP: current,
				EndIP:   endIP,
			}

			// 检查这个/24是否安全
			if isSafeCIDR(newCIDR, blockingRanges, true) {
				result = append(result, newCIDR)
			}

			// 移动到下一个/24
			next := incrementIP(endIP)
			if next == nil {
				break
			}
			current = next
		}
	} else {
		// IPv6：拆分成/64网段（简化版）
		result = append(result, cidr) // 暂时保持原样
	}

	return result
}

// createBlockingMap 创建阻塞网段的快速查找映射
func createBlockingMap(blockingRanges []IPRange) map[string]bool {
	blockingMap := make(map[string]bool)
	for _, r := range blockingRanges {
		key := fmt.Sprintf("%s-%s", r.StartIP.String(), r.EndIP.String())
		blockingMap[key] = true
	}
	return blockingMap
}

// canMergeCIDRs 检查两个CIDR是否可以合并（它们之间没有阻塞网段）
func canMergeCIDRs(cidr1, cidr2 CIDR, blockingRanges []IPRange) bool {
	// 检查是否相邻或重叠
	if compareIPs(cidr1.EndIP, cidr2.StartIP) >= 0 {
		// 重叠或相邻，可以合并
		return true
	}

	// 有空隙，需要检查空隙中是否有阻塞网段
	gapStartIP := incrementIP(cidr1.EndIP)
	gapEndIP := decrementIP(cidr2.StartIP)

	if gapStartIP == nil || gapEndIP == nil || compareIPs(gapStartIP, gapEndIP) > 0 {
		return false
	}

	// 检查空隙是否过大（适度限制）
	if isIPv4(gapStartIP) {
		// IPv4：如果空隙超过256K个IP（约16个/24），不合并
		if calculateIPCount(gapStartIP, gapEndIP) > 262144 {
			return false
		}
	} else {
		// IPv6：如果空隙超过/96，不合并
		if calculateIPv6PrefixLength(gapStartIP, gapEndIP) < 96 {
			return false
		}
	}

	// 检查空隙中是否真的有阻塞网段
	for _, blocking := range blockingRanges {
		if compareIPs(gapStartIP, blocking.EndIP) <= 0 && compareIPs(blocking.StartIP, gapEndIP) <= 0 {
			return false // 空隙中有阻塞网段，不能合并
		}
	}

	return true // 空隙中没有阻塞网段，可以合并
}

// calculateIPCount 计算两个IPv4地址之间的IP数量
func calculateIPCount(startIP, endIP net.IP) uint64 {
	if len(startIP) != 4 || len(endIP) != 4 {
		return 0
	}

	start := uint64(startIP[0])<<24 + uint64(startIP[1])<<16 + uint64(startIP[2])<<8 + uint64(startIP[3])
	end := uint64(endIP[0])<<24 + uint64(endIP[1])<<16 + uint64(endIP[2])<<8 + uint64(endIP[3])

	if end >= start {
		return end - start + 1
	}
	return 0
}

// calculateIPv6PrefixLength 估算IPv6范围对应的前缀长度
func calculateIPv6PrefixLength(startIP, endIP net.IP) int {
	if len(startIP) != 16 || len(endIP) != 16 {
		return 128
	}

	// 简化版：检查前8个字节的差异
	for i := 0; i < 8; i++ {
		if startIP[i] != endIP[i] {
			return i * 8
		}
	}

	return 64
}

// incrementIP 将IP地址加1
func incrementIP(ip net.IP) net.IP {
	result := make(net.IP, len(ip))
	copy(result, ip)

	for i := len(result) - 1; i >= 0; i-- {
		result[i]++
		if result[i] != 0 {
			return result
		}
	}

	return nil // 溢出
}

// decrementIP 将IP地址减1
func decrementIP(ip net.IP) net.IP {
	result := make(net.IP, len(ip))
	copy(result, ip)

	for i := len(result) - 1; i >= 0; i-- {
		if result[i] != 0 {
			result[i]--
			return result
		}
		result[i] = 255
	}

	return nil // 下溢
}

// extractBlockingRanges 提取中国大陆和私有网段作为阻塞范围
func extractBlockingRanges(allRanges []IPRange, isIPv4 bool) []IPRange {
	var blocking []IPRange
	for _, r := range allRanges {
		if IsMainlandChina(r.Info) && !IsPrivateOrReserved(r.StartIP, r.EndIP) {
			blocking = append(blocking, r)
		} else if IsPrivateOrReserved(r.StartIP, r.EndIP) {
			blocking = append(blocking, r)
		}
	}

	// 按起始IP排序阻塞范围
	sort.Slice(blocking, func(i, j int) bool {
		return compareIPs(blocking[i].StartIP, blocking[j].StartIP) < 0
	})

	return blocking
}

// IPRangeWithType 带类型的IP范围，用于统一处理
type IPRangeWithType struct {
	IPRange
	Type string // "china", "private", "non-china"
}

// smartMergeByAddressOrder 按地址顺序进行智能合并
func smartMergeByAddressOrder(allRanges []IPRange, isIPv4 bool) []CIDR {
	if len(allRanges) == 0 {
		return []CIDR{}
	}

	// 将所有范围标记类型并排序
	var rangesWithType []IPRangeWithType
	for _, r := range allRanges {
		rangeType := "non-china"
		if IsMainlandChina(r.Info) && !IsPrivateOrReserved(r.StartIP, r.EndIP) {
			rangeType = "china"
		} else if IsPrivateOrReserved(r.StartIP, r.EndIP) {
			rangeType = "private"
		}

		rangesWithType = append(rangesWithType, IPRangeWithType{
			IPRange: r,
			Type:    rangeType,
		})
	}

	// 按起始IP排序
	sort.Slice(rangesWithType, func(i, j int) bool {
		return compareIPs(rangesWithType[i].StartIP, rangesWithType[j].StartIP) < 0
	})

	// 扫描并识别连续的非中国网段组
	var mergedCIDRs []CIDR
	var currentGroup []IPRange

	for _, r := range rangesWithType {
		if r.Type == "non-china" {
			// 非中国网段，加入当前组
			currentGroup = append(currentGroup, r.IPRange)
		} else {
			// 遇到阻塞网段（中国或私有），处理当前组
			if len(currentGroup) > 0 {
				groupCIDRs := mergeGroupWithLimits(currentGroup, isIPv4)
				mergedCIDRs = append(mergedCIDRs, groupCIDRs...)
				currentGroup = nil
			}
		}
	}

	// 处理最后一个组
	if len(currentGroup) > 0 {
		groupCIDRs := mergeGroupWithLimits(currentGroup, isIPv4)
		mergedCIDRs = append(mergedCIDRs, groupCIDRs...)
	}

	return mergedCIDRs
}

// mergeGroupWithLimits 将一个连续的非中国网段组合并，但限制最大网段大小
func mergeGroupWithLimits(group []IPRange, isIPv4 bool) []CIDR {
	if len(group) == 0 {
		return []CIDR{}
	}

	// 如果只有一个范围，直接转换
	if len(group) == 1 {
		_, network, err := net.ParseCIDR(group[0].CIDR)
		if err == nil {
			return []CIDR{{
				Network: network,
				StartIP: group[0].StartIP,
				EndIP:   group[0].EndIP,
			}}
		}
		return []CIDR{}
	}

	// 找到组的整体范围
	startIP := group[0].StartIP
	endIP := group[0].EndIP

	for i := 1; i < len(group); i++ {
		if compareIPs(group[i].StartIP, startIP) < 0 {
			startIP = group[i].StartIP
		}
		if compareIPs(group[i].EndIP, endIP) > 0 {
			endIP = group[i].EndIP
		}
	}

	// 检查合并后的范围是否过大
	if shouldSplitLargeRange(startIP, endIP, isIPv4) {
		// 范围太大，使用传统合并方法
		return mergeGroupTraditionally(group)
	}

	// 范围合理，生成最优CIDR并验证
	cidrs := generateOptimalCIDRs(startIP, endIP, isIPv4)

	// 验证生成的CIDR，移除过大的网段
	var validCIDRs []CIDR
	for _, cidr := range cidrs {
		if isValidCIDRSize(cidr, isIPv4) {
			validCIDRs = append(validCIDRs, cidr)
		}
	}

	// 如果没有有效的CIDR，回退到传统合并
	if len(validCIDRs) == 0 {
		return mergeGroupTraditionally(group)
	}

	return validCIDRs
}

// shouldSplitLargeRange 检查范围是否过大需要拆分
func shouldSplitLargeRange(startIP, endIP net.IP, isIPv4 bool) bool {
	if isIPv4 {
		// IPv4：如果范围超过/20（约4K个IP），就拆分
		count := calculateIPCount(startIP, endIP)
		return count > 4096
	} else {
		// IPv6：如果范围超过/64，就拆分
		prefixLen := calculateIPv6PrefixLength(startIP, endIP)
		return prefixLen < 64
	}
}

// mergeGroupTraditionally 使用传统方法合并组内的范围
func mergeGroupTraditionally(group []IPRange) []CIDR {
	var cidrs []CIDR

	// 将每个范围转换为CIDR
	for _, r := range group {
		_, network, err := net.ParseCIDR(r.CIDR)
		if err == nil {
			cidrs = append(cidrs, CIDR{
				Network: network,
				StartIP: r.StartIP,
				EndIP:   r.EndIP,
			})
		}
	}

	// 使用传统的相邻合并
	return MergeCIDRs(cidrs)
}

// isValidCIDRSize 检查CIDR的大小是否合理
func isValidCIDRSize(cidr CIDR, isIPv4 bool) bool {
	if cidr.Network == nil {
		return false
	}

	prefixLen, _ := cidr.Network.Mask.Size()

	if isIPv4 {
		// IPv4：不允许前缀长度小于/16的网段
		return prefixLen >= 16
	} else {
		// IPv6：不允许前缀长度小于/56的网段
		return prefixLen >= 56
	}
}

// generateConservativeCIDRs 生成保守的CIDR列表，实现跨空隙合并但限制最大范围
func generateConservativeCIDRs(ranges []IPRange, isIPv4 bool) []CIDR {
	if len(ranges) == 0 {
		return []CIDR{}
	}

	// 如果只有一个范围，直接转换
	if len(ranges) == 1 {
		_, network, err := net.ParseCIDR(ranges[0].CIDR)
		if err == nil {
			return []CIDR{{
				Network: network,
				StartIP: ranges[0].StartIP,
				EndIP:   ranges[0].EndIP,
			}}
		}
		return []CIDR{}
	}

	// 多个范围：找到整个组的起始和结束IP
	startIP := ranges[0].StartIP
	endIP := ranges[0].EndIP

	for i := 1; i < len(ranges); i++ {
		if compareIPs(ranges[i].StartIP, startIP) < 0 {
			startIP = ranges[i].StartIP
		}
		if compareIPs(ranges[i].EndIP, endIP) > 0 {
			endIP = ranges[i].EndIP
		}
	}

	// 检查范围是否过大，避免生成过大的网段
	maxPrefix := 4 // IPv4最小前缀/4，IPv6最小前缀/16
	if !isIPv4 {
		maxPrefix = 16
	}

	// 计算覆盖整个范围需要的最小前缀
	var bits int
	if isIPv4 {
		bits = 32
	} else {
		bits = 128
	}

	minRequiredPrefix := bits
	for prefix := 0; prefix <= bits; prefix++ {
		mask := net.CIDRMask(prefix, bits)
		network := &net.IPNet{IP: startIP.Mask(mask), Mask: mask}
		if network.Contains(startIP) && network.Contains(endIP) {
			minRequiredPrefix = prefix
			break
		}
	}

	// 如果需要的前缀太小（网段太大），则使用传统合并
	if minRequiredPrefix < maxPrefix {
		var cidrs []CIDR
		for _, r := range ranges {
			_, network, err := net.ParseCIDR(r.CIDR)
			if err == nil {
				cidrs = append(cidrs, CIDR{
					Network: network,
					StartIP: r.StartIP,
					EndIP:   r.EndIP,
				})
			}
		}
		return MergeCIDRs(cidrs)
	}

	// 生成覆盖整个范围的最优CIDR列表
	return generateOptimalCIDRs(startIP, endIP, isIPv4)
}

// deduplicateAndOptimizeCIDRs 去重并优化CIDR列表
func deduplicateAndOptimizeCIDRs(cidrs []CIDR) []CIDR {
	if len(cidrs) == 0 {
		return cidrs
	}

	// 使用map去重
	cidrMap := make(map[string]CIDR)
	for _, cidr := range cidrs {
		key := cidr.Network.String()
		cidrMap[key] = cidr
	}

	// 转换回slice
	var uniqueCIDRs []CIDR
	for _, cidr := range cidrMap {
		uniqueCIDRs = append(uniqueCIDRs, cidr)
	}

	// 排序并最终合并
	sort.Slice(uniqueCIDRs, func(i, j int) bool {
		return compareIPs(uniqueCIDRs[i].StartIP, uniqueCIDRs[j].StartIP) < 0
	})

	return MergeCIDRs(uniqueCIDRs)
}

// generateOptimalCIDRs 生成覆盖指定IP范围的最优CIDR列表
func generateOptimalCIDRs(startIP, endIP net.IP, isIPv4 bool) []CIDR {
	var cidrs []CIDR
	var bits int
	if isIPv4 {
		bits = 32
	} else {
		bits = 128
	}

	current := make(net.IP, len(startIP))
	copy(current, startIP)

	for compareIPs(current, endIP) <= 0 {
		// 找到从当前IP开始的最大可能CIDR
		maxPrefix := findMaxPrefix(current, endIP, bits)

		mask := net.CIDRMask(maxPrefix, bits)
		network := &net.IPNet{IP: current.Mask(mask), Mask: mask}

		cidrs = append(cidrs, CIDR{
			Network: network,
			StartIP: network.IP,
			EndIP:   calculateNetworkEndIP(network),
		})

		// 移动到下一个网络块
		current = incrementIP(calculateNetworkEndIP(network))
		if current == nil {
			break
		}
	}

	return cidrs
}

// findMaxPrefix 找到从startIP开始不超过endIP的最大前缀长度
func findMaxPrefix(startIP, endIP net.IP, bits int) int {
	for prefix := 0; prefix <= bits; prefix++ {
		mask := net.CIDRMask(prefix, bits)
		network := &net.IPNet{IP: startIP.Mask(mask), Mask: mask}
		networkEnd := calculateNetworkEndIP(network)

		if compareIPs(networkEnd, endIP) > 0 {
			return prefix + 1
		}

		// 检查startIP是否在网络边界上
		if !startIP.Equal(network.IP) {
			return prefix + 1
		}
	}
	return bits
}
