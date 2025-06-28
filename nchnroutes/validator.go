package nchnroutes

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/ipipdotnet/ipdb-go"
)

// ValidationResult 验证结果
type ValidationResult struct {
	TotalCIDRs          int
	TotalIPsChecked     int
	ChinaMainlandFound  int
	PrivateAddressFound int
	InvalidAddressFound int
	ValidNonChinaFound  int
	SamplesPerCIDR      int
	ChinaMainlandIPs    []string
	PrivateIPs          []string
	InvalidIPs          []string
}

// IPValidator IP验证器
type IPValidator struct {
	cityDB    *ipdb.City
	validator *ValidationResult
}

// NewIPValidator 创建新的IP验证器
func NewIPValidator(dbPath string, samplesPerCIDR int) (*IPValidator, error) {
	db, err := ipdb.NewCity(dbPath)
	if err != nil {
		return nil, fmt.Errorf("无法加载IPDB数据库: %v", err)
	}

	return &IPValidator{
		cityDB: db,
		validator: &ValidationResult{
			SamplesPerCIDR:   samplesPerCIDR,
			ChinaMainlandIPs: []string{},
			PrivateIPs:       []string{},
			InvalidIPs:       []string{},
		},
	}, nil
}

// ExtractCIDRsFromBirdConfig 从bird配置文件中提取CIDR列表
func (v *IPValidator) ExtractCIDRsFromBirdConfig(filePath string) ([]string, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var cidrs []string
	scanner := bufio.NewScanner(file)

	// 匹配Bird路由配置的正则表达式: route <cidr> via "<interface>";
	routeRegex := regexp.MustCompile(`^\s*route\s+([0-9a-fA-F:.]+/\d+)\s+via\s+"[^"]+"\s*;\s*$`)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		// 跳过注释和空行
		if strings.HasPrefix(line, "#") || line == "" {
			continue
		}

		// 提取路由配置中的CIDR
		matches := routeRegex.FindStringSubmatch(line)
		if len(matches) > 1 {
			cidrs = append(cidrs, matches[1])
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return cidrs, nil
}

// ValidateIP 验证单个IP地址
func (v *IPValidator) ValidateIP(ip string) (bool, error) {
	// 检查是否为私有地址
	if v.isPrivateOrReservedIP(ip) {
		v.validator.PrivateAddressFound++
		v.validator.PrivateIPs = append(v.validator.PrivateIPs, ip)
		return false, nil
	}

	// 使用IPDB查询地理位置信息
	info, err := v.cityDB.FindInfo(ip, "CN")
	if err != nil {
		v.validator.InvalidAddressFound++
		v.validator.InvalidIPs = append(v.validator.InvalidIPs, ip)
		return false, fmt.Errorf("查询IP %s 失败: %v", ip, err)
	}

	// 检查是否为中国大陆地址
	if v.isChinaMainland(info) {
		v.validator.ChinaMainlandFound++
		v.validator.ChinaMainlandIPs = append(v.validator.ChinaMainlandIPs,
			fmt.Sprintf("%s -> %s, %s, %s", ip, info.CountryName, info.RegionName, info.CityName))
		return false, nil
	}

	v.validator.ValidNonChinaFound++
	return true, nil
}

// isChinaMainland 判断是否为中国大陆地址
func (v *IPValidator) isChinaMainland(info *ipdb.CityInfo) bool {
	countryName := strings.ToLower(info.CountryName)
	regionName := strings.ToLower(info.RegionName)

	// 中国大陆的判断条件
	if strings.Contains(countryName, "中国") || countryName == "china" {
		// 排除香港、澳门、台湾
		if strings.Contains(regionName, "香港") || strings.Contains(regionName, "hong kong") ||
			strings.Contains(regionName, "澳门") || strings.Contains(regionName, "macao") ||
			strings.Contains(regionName, "台湾") || strings.Contains(regionName, "taiwan") {
			return false
		}
		return true
	}
	return false
}

// isPrivateOrReservedIP 判断是否为私有或保留地址
func (v *IPValidator) isPrivateOrReservedIP(ipStr string) bool {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}

	// IPv4私有地址范围
	if ip.To4() != nil {
		// 10.0.0.0/8
		if ip[12] == 10 {
			return true
		}
		// 172.16.0.0/12
		if ip[12] == 172 && (ip[13] >= 16 && ip[13] <= 31) {
			return true
		}
		// 192.168.0.0/16
		if ip[12] == 192 && ip[13] == 168 {
			return true
		}
		// 127.0.0.0/8 (回环地址)
		if ip[12] == 127 {
			return true
		}
		// 169.254.0.0/16 (链路本地地址)
		if ip[12] == 169 && ip[13] == 254 {
			return true
		}
		// 224.0.0.0/4 (多播地址)
		if ip[12] >= 224 && ip[12] <= 239 {
			return true
		}
		// 240.0.0.0/4 (保留地址)
		if ip[12] >= 240 {
			return true
		}
	} else {
		// IPv6私有和保留地址
		// ::1/128 (回环地址)
		if ip.IsLoopback() {
			return true
		}
		// fe80::/10 (链路本地地址)
		if ip[0] == 0xfe && (ip[1]&0xc0) == 0x80 {
			return true
		}
		// fc00::/7 (唯一本地地址)
		if (ip[0] & 0xfe) == 0xfc {
			return true
		}
		// ff00::/8 (多播地址)
		if ip[0] == 0xff {
			return true
		}
	}

	return false
}

// GenerateSampleIPs 生成CIDR中的样本IP地址
func (v *IPValidator) GenerateSampleIPs(cidr string, sampleCount int) ([]string, error) {
	_, network, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, err
	}

	var ips []string
	ip := network.IP

	// 对于较小的网络，生成所有IP
	ones, bits := network.Mask.Size()
	if bits-ones < 0 || bits-ones > 30 {
		// 避免无效的网络配置或过大的网络
		return []string{network.IP.String()}, nil
	}
	totalHosts := 1 << (bits - ones)

	if totalHosts <= sampleCount {
		// 生成所有IP
		for i := 0; i < totalHosts; i++ {
			ips = append(ips, ip.String())
			ip = v.nextIP(ip)
			if !network.Contains(ip) {
				break
			}
		}
	} else {
		// 生成样本IP：开始、中间几个点、结束
		ips = append(ips, ip.String()) // 第一个IP

		if sampleCount <= 1 {
			return []string{network.IP.String()}, nil
		}
		step := totalHosts / (sampleCount - 1)
		for i := 1; i < sampleCount-1; i++ {
			sampleIP := v.addToIP(network.IP, i*step)
			if network.Contains(sampleIP) {
				ips = append(ips, sampleIP.String())
			}
		}

		// 最后一个IP
		lastIP := v.addToIP(network.IP, totalHosts-1)
		if network.Contains(lastIP) {
			ips = append(ips, lastIP.String())
		}
	}

	return ips, nil
}

// nextIP 计算下一个IP地址
func (v *IPValidator) nextIP(ip net.IP) net.IP {
	next := make(net.IP, len(ip))
	copy(next, ip)

	for i := len(next) - 1; i >= 0; i-- {
		next[i]++
		if next[i] != 0 {
			break
		}
	}

	return next
}

// addToIP 给IP地址加上偏移量
func (v *IPValidator) addToIP(ip net.IP, offset int) net.IP {
	result := make(net.IP, len(ip))
	copy(result, ip)

	carry := offset
	for i := len(result) - 1; i >= 0 && carry > 0; i-- {
		sum := int(result[i]) + carry
		result[i] = byte(sum & 0xff)
		carry = sum >> 8
	}

	return result
}

// ValidateCIDRs 验证所有CIDR
func (v *IPValidator) ValidateCIDRs(cidrs []string) {
	fmt.Printf("开始验证 %d 个CIDR，每个CIDR采样 %d 个IP地址...\n",
		len(cidrs), v.validator.SamplesPerCIDR)

	v.validator.TotalCIDRs = len(cidrs)

	for i, cidr := range cidrs {
		if i%1000 == 0 {
			fmt.Printf("进度: %d/%d (%.1f%%)\n", i, len(cidrs), float64(i)*100/float64(len(cidrs)))
		}

		ips, err := v.GenerateSampleIPs(cidr, v.validator.SamplesPerCIDR)
		if err != nil {
			fmt.Printf("生成CIDR %s 的样本IP失败: %v\n", cidr, err)
			continue
		}

		for _, ip := range ips {
			v.validator.TotalIPsChecked++
			_, err := v.ValidateIP(ip)
			if err != nil {
				// 错误已经在ValidateIP中处理
			}
		}
	}
}

// GenerateReport 生成验证报告
func (v *IPValidator) GenerateReport() {
	fmt.Println("\n" + strings.Repeat("=", 80))
	fmt.Println("CIDR验证报告")
	fmt.Println(strings.Repeat("=", 80))

	fmt.Printf("验证时间: %s\n", time.Now().Format("2006-01-02 15:04:05"))
	fmt.Printf("总CIDR数量: %d\n", v.validator.TotalCIDRs)
	fmt.Printf("总检查IP数量: %d\n", v.validator.TotalIPsChecked)
	fmt.Printf("每个CIDR采样数: %d\n", v.validator.SamplesPerCIDR)

	fmt.Println("\n验证结果:")
	fmt.Printf("✅ 有效的非中国地址: %d (%.2f%%)\n",
		v.validator.ValidNonChinaFound,
		float64(v.validator.ValidNonChinaFound)*100/float64(v.validator.TotalIPsChecked))

	fmt.Printf("❌ 发现的中国大陆地址: %d (%.2f%%)\n",
		v.validator.ChinaMainlandFound,
		float64(v.validator.ChinaMainlandFound)*100/float64(v.validator.TotalIPsChecked))

	fmt.Printf("❌ 发现的私有地址: %d (%.2f%%)\n",
		v.validator.PrivateAddressFound,
		float64(v.validator.PrivateAddressFound)*100/float64(v.validator.TotalIPsChecked))

	fmt.Printf("⚠️  无效地址: %d (%.2f%%)\n",
		v.validator.InvalidAddressFound,
		float64(v.validator.InvalidAddressFound)*100/float64(v.validator.TotalIPsChecked))

	// 详细错误信息
	if len(v.validator.ChinaMainlandIPs) > 0 {
		fmt.Println("\n发现的中国大陆地址 (前10个):")
		count := len(v.validator.ChinaMainlandIPs)
		if count > 10 {
			count = 10
		}
		for i := 0; i < count; i++ {
			fmt.Printf("  %s\n", v.validator.ChinaMainlandIPs[i])
		}
		if len(v.validator.ChinaMainlandIPs) > 10 {
			fmt.Printf("  ... 还有 %d 个\n", len(v.validator.ChinaMainlandIPs)-10)
		}
	}

	if len(v.validator.PrivateIPs) > 0 {
		fmt.Println("\n发现的私有地址 (前10个):")
		count := len(v.validator.PrivateIPs)
		if count > 10 {
			count = 10
		}
		for i := 0; i < count; i++ {
			fmt.Printf("  %s\n", v.validator.PrivateIPs[i])
		}
		if len(v.validator.PrivateIPs) > 10 {
			fmt.Printf("  ... 还有 %d 个\n", len(v.validator.PrivateIPs)-10)
		}
	}

	fmt.Println(strings.Repeat("=", 80))

	// 验证结论
	if v.validator.ChinaMainlandFound == 0 && v.validator.PrivateAddressFound == 0 {
		fmt.Println("✅ 验证通过：所有采样IP地址都已正确排除中国大陆和私有地址")
	} else {
		fmt.Println("❌ 验证失败：发现了中国大陆地址或私有地址")
	}
}
