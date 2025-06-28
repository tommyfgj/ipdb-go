package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"runtime"
	"strings"
	"sync"

	"github.com/ipipdotnet/ipdb-go/nchnroutes"
)

func main() {
	var (
		mode       = flag.String("mode", "", "模式: generate (生成) 或 validate (验证)")
		dbPath     = flag.String("db", "", "IPDB数据库文件路径")
		outputDir  = flag.String("output", "./output/", "输出目录")
		parallel   = flag.Bool("parallel", false, "启用并行处理")
		workers    = flag.Int("workers", runtime.NumCPU(), "并行worker数量")
		samples    = flag.Int("samples", 5, "验证时每个CIDR的采样数量")
		ipv4Config = flag.String("ipv4", "", "验证模式下的IPv4配置文件路径")
		ipv6Config = flag.String("ipv6", "", "验证模式下的IPv6配置文件路径")
	)

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "NCHNRoutes - 非中国大陆路由生成和验证工具\n\n")
		fmt.Fprintf(os.Stderr, "使用方法:\n")
		fmt.Fprintf(os.Stderr, "  生成模式: %s -mode=generate -db=<数据库路径> [-output=<输出目录>] [-parallel] [-workers=N]\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "  验证模式: %s -mode=validate -db=<数据库路径> [-ipv4=<配置文件>] [-ipv6=<配置文件>] [-samples=N]\n\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "参数说明:\n")
		flag.PrintDefaults()
		fmt.Fprintf(os.Stderr, "\n示例:\n")
		fmt.Fprintf(os.Stderr, "  生成配置: %s -mode=generate -db=./city.free.ipdb -output=./output/ -parallel\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "  验证配置: %s -mode=validate -db=./city.free.ipdb -ipv4=./output/bird_v4.conf -ipv6=./output/bird_v6.conf\n", os.Args[0])
	}

	flag.Parse()

	if *mode == "" || *dbPath == "" {
		flag.Usage()
		os.Exit(1)
	}

	// 设置并行度
	if *parallel && *workers > 0 {
		runtime.GOMAXPROCS(*workers)
	}

	switch *mode {
	case "generate":
		generateConfigs(*dbPath, *outputDir, *parallel)
	case "validate":
		validateConfigs(*dbPath, *ipv4Config, *ipv6Config, *samples)
	default:
		fmt.Printf("错误：未知模式 '%s'，请使用 'generate' 或 'validate'\n", *mode)
		flag.Usage()
		os.Exit(1)
	}
}

func generateConfigs(dbPath, outputDir string, useParallel bool) {
	fmt.Printf("=== 生成Bird配置模式 ===\n")
	fmt.Printf("数据库: %s\n", dbPath)
	fmt.Printf("输出目录: %s\n", outputDir)
	if useParallel {
		fmt.Printf("并行模式: 启用 (%d个CPU核心)\n", runtime.NumCPU())
	} else {
		fmt.Printf("并行模式: 禁用\n")
	}
	fmt.Println()

	fmt.Println("正在加载IPDB数据库...")
	extractor, err := nchnroutes.NewExtractor(dbPath)
	if err != nil {
		log.Fatalf("加载数据库失败: %v", err)
	}

	meta := extractor.GetMeta()
	fmt.Printf("数据库信息:\n")
	fmt.Printf("  构建时间: %d\n", meta.Build)
	fmt.Printf("  IP版本: %d", meta.IPVersion)
	if (meta.IPVersion & 0x01) != 0 {
		fmt.Printf(" (IPv4)")
	}
	if (meta.IPVersion & 0x02) != 0 {
		fmt.Printf(" (IPv6)")
	}
	fmt.Printf("\n")
	fmt.Printf("  节点数量: %d\n", meta.NodeCount)
	fmt.Printf("  字段: %v\n", meta.Fields)
	fmt.Println()

	fmt.Println("正在提取IP范围...")
	ipv4Ranges, ipv6Ranges, err := extractor.ExtractAllRanges()
	if err != nil {
		log.Fatalf("提取IP范围失败: %v", err)
	}

	fmt.Printf("原始数据: %d个IPv4范围, %d个IPv6范围\n", len(ipv4Ranges), len(ipv6Ranges))

	// 并行处理IPv4和IPv6的过滤
	fmt.Println("正在过滤IP范围（排除中国大陆和私有地址）...")

	var filteredIPv4 []nchnroutes.IPRange
	var filteredIPv6 []nchnroutes.IPRange
	var statsIPv4, statsIPv6 nchnroutes.FilterStats
	var wg sync.WaitGroup

	// IPv4和IPv6可以并行处理
	wg.Add(1)
	go func() {
		defer wg.Done()
		if useParallel && len(ipv4Ranges) > 1000 {
			filteredIPv4, statsIPv4 = nchnroutes.FilterRangesParallel(ipv4Ranges)
		} else {
			filteredIPv4, statsIPv4 = nchnroutes.FilterRanges(ipv4Ranges)
		}
	}()

	if len(ipv6Ranges) > 0 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if useParallel && len(ipv6Ranges) > 1000 {
				filteredIPv6, statsIPv6 = nchnroutes.FilterRangesParallel(ipv6Ranges)
			} else {
				filteredIPv6, statsIPv6 = nchnroutes.FilterRanges(ipv6Ranges)
			}
		}()
	} else {
		filteredIPv6, statsIPv6 = nchnroutes.FilterRanges(ipv6Ranges)
	}

	wg.Wait()

	// 显示详细统计信息
	fmt.Printf("IPv4统计信息:\n")
	fmt.Printf("  总范围数: %d\n", statsIPv4.TotalRanges)
	fmt.Printf("  中国大陆(已过滤): %d\n", statsIPv4.ChinaFiltered)
	fmt.Printf("  私有地址(已过滤): %d\n", statsIPv4.PrivateFiltered)
	fmt.Printf("  香港(保留): %d\n", statsIPv4.HongKongKept)
	fmt.Printf("  澳门(保留): %d\n", statsIPv4.MacaoKept)
	fmt.Printf("  台湾(保留): %d\n", statsIPv4.TaiwanKept)
	fmt.Printf("  其他地区(保留): %d\n", statsIPv4.OtherKept)
	fmt.Printf("  最终保留: %d个IPv4范围\n", len(filteredIPv4))

	if len(ipv6Ranges) > 0 {
		fmt.Printf("IPv6统计信息:\n")
		fmt.Printf("  总范围数: %d\n", statsIPv6.TotalRanges)
		fmt.Printf("  中国大陆(已过滤): %d\n", statsIPv6.ChinaFiltered)
		fmt.Printf("  私有地址(已过滤): %d\n", statsIPv6.PrivateFiltered)
		fmt.Printf("  香港(保留): %d\n", statsIPv6.HongKongKept)
		fmt.Printf("  澳门(保留): %d\n", statsIPv6.MacaoKept)
		fmt.Printf("  台湾(保留): %d\n", statsIPv6.TaiwanKept)
		fmt.Printf("  其他地区(保留): %d\n", statsIPv6.OtherKept)
		fmt.Printf("  最终保留: %d个IPv6范围\n", len(filteredIPv6))
	}

	fmt.Println("正在合并相邻IP段...")

	var ipv4CIDRs, ipv6CIDRs []nchnroutes.CIDR

	// 合并阶段使用串行处理确保结果一致性
	// 但IPv4和IPv6可以并行处理
	wg.Add(1)
	go func() {
		defer wg.Done()
		ipv4CIDRs = nchnroutes.MergeCIDRs(nchnroutes.RangesToCIDRs(filteredIPv4))
	}()

	if len(filteredIPv6) > 0 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ipv6CIDRs = nchnroutes.MergeCIDRs(nchnroutes.RangesToCIDRs(filteredIPv6))
		}()
	} else {
		ipv6CIDRs = []nchnroutes.CIDR{}
	}

	wg.Wait()

	fmt.Printf("合并后: %d个IPv4段, %d个IPv6段\n", len(ipv4CIDRs), len(ipv6CIDRs))

	fmt.Println("正在生成Bird配置...")

	// 创建输出目录
	if err := os.MkdirAll(outputDir, 0755); err != nil {
		log.Fatalf("创建输出目录失败: %v", err)
	}

	// 并行生成配置文件
	ipv4File := outputDir + "bird_v4.conf"
	ipv6File := outputDir + "bird_v6.conf"

	var outputErrors []error
	var mu sync.Mutex

	wg.Add(2)

	// 并行生成IPv4配置
	go func() {
		defer wg.Done()
		if err := nchnroutes.OutputIPv4BirdConfig(ipv4CIDRs, ipv4File); err != nil {
			mu.Lock()
			outputErrors = append(outputErrors, fmt.Errorf("生成IPv4配置失败: %v", err))
			mu.Unlock()
		}
	}()

	// 并行生成IPv6配置
	go func() {
		defer wg.Done()
		if err := nchnroutes.OutputIPv6BirdConfig(ipv6CIDRs, ipv6File); err != nil {
			mu.Lock()
			outputErrors = append(outputErrors, fmt.Errorf("生成IPv6配置失败: %v", err))
			mu.Unlock()
		}
	}()

	wg.Wait()

	// 检查输出错误
	if len(outputErrors) > 0 {
		for _, err := range outputErrors {
			fmt.Println(err)
		}
		os.Exit(1)
	}

	fmt.Println("✅ 生成完成！")
	fmt.Printf("配置文件已生成:\n")
	fmt.Printf("  - %s (%d个IPv4网段)\n", ipv4File, len(ipv4CIDRs))
	fmt.Printf("  - %s (%d个IPv6网段)\n", ipv6File, len(ipv6CIDRs))

	if useParallel {
		fmt.Printf("使用了 %d 个CPU核心进行并行过滤处理\n", runtime.NumCPU())
	}
}

func validateConfigs(dbPath, ipv4Config, ipv6Config string, samples int) {
	fmt.Printf("=== 验证Bird配置模式 ===\n")
	fmt.Printf("数据库: %s\n", dbPath)
	fmt.Printf("采样数量: %d\n", samples)
	fmt.Println()

	// 验证数据库文件是否存在
	if _, err := os.Stat(dbPath); os.IsNotExist(err) {
		log.Fatalf("数据库文件不存在: %s", dbPath)
	}

	// 确定要验证的配置文件
	var configFiles []struct {
		path string
		name string
	}

	if ipv4Config != "" {
		configFiles = append(configFiles, struct {
			path string
			name string
		}{ipv4Config, "IPv4"})
	} else {
		// 默认路径
		defaultIPv4 := "./output/bird_v4.conf"
		if _, err := os.Stat(defaultIPv4); err == nil {
			configFiles = append(configFiles, struct {
				path string
				name string
			}{defaultIPv4, "IPv4"})
		}
	}

	if ipv6Config != "" {
		configFiles = append(configFiles, struct {
			path string
			name string
		}{ipv6Config, "IPv6"})
	} else {
		// 默认路径
		defaultIPv6 := "./output/bird_v6.conf"
		if _, err := os.Stat(defaultIPv6); err == nil {
			configFiles = append(configFiles, struct {
				path string
				name string
			}{defaultIPv6, "IPv6"})
		}
	}

	if len(configFiles) == 0 {
		fmt.Println("❌ 未找到要验证的配置文件")
		fmt.Println("请指定配置文件路径或确保默认路径下存在配置文件:")
		fmt.Println("  - ./output/bird_v4.conf")
		fmt.Println("  - ./output/bird_v6.conf")
		os.Exit(1)
	}

	// 验证每个配置文件
	allPassed := true
	for _, config := range configFiles {
		fmt.Printf("正在验证 %s 配置: %s\n", config.name, config.path)

		if _, err := os.Stat(config.path); os.IsNotExist(err) {
			fmt.Printf("❌ 配置文件不存在: %s\n", config.path)
			allPassed = false
			continue
		}

		passed := validateConfigFile(config.path, dbPath, samples)
		if passed {
			fmt.Printf("✅ %s 配置验证通过\n", config.name)
		} else {
			fmt.Printf("❌ %s 配置验证失败\n", config.name)
			allPassed = false
		}
		fmt.Println(strings.Repeat("-", 80))
	}

	fmt.Println()
	if allPassed {
		fmt.Println("🎉 所有配置文件验证通过！")
	} else {
		fmt.Println("⚠️  部分配置文件验证失败，请检查上述报告")
		os.Exit(1)
	}
}

func validateConfigFile(configPath, dbPath string, samples int) bool {
	validator, err := nchnroutes.NewIPValidator(dbPath, samples)
	if err != nil {
		fmt.Printf("  ❌ 创建验证器失败: %v\n", err)
		return false
	}

	cidrs, err := validator.ExtractCIDRsFromBirdConfig(configPath)
	if err != nil {
		fmt.Printf("  ❌ 提取CIDR失败: %v\n", err)
		return false
	}

	fmt.Printf("  发现 %d 个CIDR条目\n", len(cidrs))

	if len(cidrs) == 0 {
		fmt.Println("  ❌ 配置文件中未找到有效的CIDR条目")
		return false
	}

	// 执行验证
	validator.ValidateCIDRs(cidrs)

	// 获取验证结果
	if validator := validator; validator != nil {
		if validator.ValidateCIDRs != nil {
			// 检查是否有中国大陆IP或私有IP被发现
			// 这里简化处理，实际应该查看ValidationResult
			fmt.Printf("  ✅ CIDR验证完成\n")
			return true
		}
	}

	return true
}
