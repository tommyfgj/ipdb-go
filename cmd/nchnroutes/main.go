package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/ipipdotnet/ipdb-go/nchnroutes"
)

func main() {
	var (
		mode          = flag.String("mode", "", "模式: generate (生成) 或 check (检查)")
		dbPath        = flag.String("db", "", "IPDB数据库文件路径")
		outputDir     = flag.String("output", "./output/", "输出目录")
		parallel      = flag.Bool("parallel", false, "启用并行处理")
		workers       = flag.Int("workers", runtime.NumCPU(), "并行worker数量")
		samples       = flag.Int("samples", 5, "检查时每个CIDR的采样数量")
		iface         = flag.String("interface", "wg0", "Bird路由配置中的接口名称")
		checkChina    = flag.Bool("check-china", true, "检查模式下是否验证中国大陆路由")
		checkNonChina = flag.Bool("check-non-china", true, "检查模式下是否验证非中国大陆路由")
		verbose       = flag.Bool("verbose", false, "显示详细的检查信息")
	)

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "NCHNRoutes - 非中国大陆路由生成和验证工具\n\n")
		fmt.Fprintf(os.Stderr, "使用方法:\n")
		fmt.Fprintf(os.Stderr, "  生成模式: %s -mode=generate -db=<数据库路径> [-output=<输出目录>] [-interface=<接口名>] [-parallel] [-workers=N]\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "  检查模式: %s -mode=check -db=<数据库路径> [-output=<输出目录>] [-check-china] [-check-non-china] [-verbose] [-samples=N]\n\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "参数说明:\n")
		flag.PrintDefaults()
		fmt.Fprintf(os.Stderr, "\n示例:\n")
		fmt.Fprintf(os.Stderr, "  生成配置: %s -mode=generate -db=./city.free.ipdb -output=./output/ -interface=tun0 -parallel\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "  检查结果: %s -mode=check -db=./city.free.ipdb -output=./output/ -verbose\n", os.Args[0])
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
		generateConfigs(*dbPath, *outputDir, *iface, *parallel)
	case "check":
		checkConfigs(*dbPath, *outputDir, *checkChina, *checkNonChina, *verbose, *samples)
	default:
		fmt.Printf("错误：未知模式 '%s'，请使用 'generate' 或 'check'\n", *mode)
		flag.Usage()
		os.Exit(1)
	}
}

func generateConfigs(dbPath, outputDir, iface string, useParallel bool) {
	fmt.Printf("=== 生成Bird配置模式 ===\n")
	fmt.Printf("数据库: %s\n", dbPath)
	fmt.Printf("输出目录: %s\n", outputDir)
	fmt.Printf("接口名称: %s\n", iface)
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
	var chinaIPv4 []nchnroutes.IPRange // 收集中国大陆IPv4范围
	var chinaIPv6 []nchnroutes.IPRange // 收集中国大陆IPv6范围
	var statsIPv4, statsIPv6 nchnroutes.FilterStats
	var wg sync.WaitGroup

	// IPv4和IPv6可以并行处理
	wg.Add(1)
	go func() {
		defer wg.Done()
		if useParallel && len(ipv4Ranges) > 1000 {
			filteredIPv4, chinaIPv4, statsIPv4 = nchnroutes.FilterRangesParallel(ipv4Ranges)
		} else {
			filteredIPv4, chinaIPv4, statsIPv4 = nchnroutes.FilterRanges(ipv4Ranges)
		}
	}()

	if len(ipv6Ranges) > 0 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if useParallel && len(ipv6Ranges) > 1000 {
				filteredIPv6, chinaIPv6, statsIPv6 = nchnroutes.FilterRangesParallel(ipv6Ranges)
			} else {
				filteredIPv6, chinaIPv6, statsIPv6 = nchnroutes.FilterRanges(ipv6Ranges)
			}
		}()
	} else {
		filteredIPv6, chinaIPv6, statsIPv6 = nchnroutes.FilterRanges(ipv6Ranges)
	}

	wg.Wait()

	// 显示详细统计信息
	fmt.Printf("IPv4统计信息:\n")
	fmt.Printf("  总范围数: %d\n", statsIPv4.TotalRanges)
	fmt.Printf("  中国大陆(已过滤): %d\n", statsIPv4.ChinaFiltered)
	fmt.Printf("  中国大陆CIDR(已保存): %d\n", statsIPv4.ChinaCIDRsSaved)
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
		fmt.Printf("  中国大陆CIDR(已保存): %d\n", statsIPv6.ChinaCIDRsSaved)
		fmt.Printf("  私有地址(已过滤): %d\n", statsIPv6.PrivateFiltered)
		fmt.Printf("  香港(保留): %d\n", statsIPv6.HongKongKept)
		fmt.Printf("  澳门(保留): %d\n", statsIPv6.MacaoKept)
		fmt.Printf("  台湾(保留): %d\n", statsIPv6.TaiwanKept)
		fmt.Printf("  其他地区(保留): %d\n", statsIPv6.OtherKept)
		fmt.Printf("  最终保留: %d个IPv6范围\n", len(filteredIPv6))
	}

	// 保存中国大陆路由
	fmt.Println("正在保存中国大陆路由...")
	if err := nchnroutes.SaveChinaRoutes(chinaIPv4, chinaIPv6, outputDir); err != nil {
		fmt.Printf("⚠️  保存中国大陆路由时出现警告: %v\n", err)
	}

	// 使用智能合并，传入所有原始数据以便精确判断
	ipv4CIDRs, ipv6CIDRs := nchnroutes.SmartMergeNonChinaCIDRs(ipv4Ranges, ipv6Ranges, filteredIPv4, filteredIPv6)

	fmt.Printf("智能合并后: %d个IPv4段, %d个IPv6段\n", len(ipv4CIDRs), len(ipv6CIDRs))

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
		if err := nchnroutes.OutputIPv4BirdConfig(ipv4CIDRs, ipv4File, iface); err != nil {
			mu.Lock()
			outputErrors = append(outputErrors, fmt.Errorf("生成IPv4配置失败: %v", err))
			mu.Unlock()
		}
	}()

	// 并行生成IPv6配置
	go func() {
		defer wg.Done()
		if err := nchnroutes.OutputIPv6BirdConfig(ipv6CIDRs, ipv6File, iface); err != nil {
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
	fmt.Printf("中国大陆路由文件:\n")
	if len(chinaIPv4) > 0 {
		fmt.Printf("  - %schnroute-ipv4.txt\n", outputDir)
	}
	if len(chinaIPv6) > 0 {
		fmt.Printf("  - %schnroute-ipv6.txt\n", outputDir)
	}

	if useParallel {
		fmt.Printf("使用了 %d 个CPU核心进行并行过滤处理\n", runtime.NumCPU())
	}
}

func checkConfigs(dbPath, outputDir string, checkChina, checkNonChina, verbose bool, samples int) {
	fmt.Printf("=== 检查路由配置模式 ===\n")
	fmt.Printf("数据库: %s\n", dbPath)
	fmt.Printf("输出目录: %s\n", outputDir)
	fmt.Printf("检查中国大陆路由: %v\n", checkChina)
	fmt.Printf("检查非中国大陆路由: %v\n", checkNonChina)
	fmt.Printf("显示详细信息: %v\n", verbose)
	fmt.Printf("采样数量: %d\n", samples)
	fmt.Println()

	// 验证数据库文件是否存在
	if _, err := os.Stat(dbPath); os.IsNotExist(err) {
		log.Fatalf("数据库文件不存在: %s", dbPath)
	}

	// 创建验证器
	validator, err := nchnroutes.NewIPValidator(dbPath, samples)
	if err != nil {
		log.Fatalf("创建验证器失败: %v", err)
	}

	var checkResults []struct {
		name     string
		category string
		passed   bool
		error    error
	}

	// 检查中国大陆路由
	if checkChina {
		fmt.Println("🔍 检查中国大陆路由...")

		chinaIPv4File := outputDir + "chnroute-ipv4.txt"
		chinaIPv6File := outputDir + "chnroute-ipv6.txt"

		// 检查IPv4中国大陆路由
		if _, err := os.Stat(chinaIPv4File); err == nil {
			fmt.Printf("正在检查IPv4中国大陆路由: %s\n", chinaIPv4File)
			passed, err := validator.CheckChinaRoutes(chinaIPv4File)
			checkResults = append(checkResults, struct {
				name     string
				category string
				passed   bool
				error    error
			}{"IPv4中国大陆路由", "中国大陆", passed, err})

			if passed {
				fmt.Printf("✅ IPv4中国大陆路由检查通过\n")
			} else if err != nil {
				fmt.Printf("❌ IPv4中国大陆路由检查出错: %v\n", err)
			} else {
				fmt.Printf("⚠️  IPv4中国大陆路由检查未完全通过\n")
			}
		} else {
			fmt.Printf("⚠️  IPv4中国大陆路由文件不存在: %s\n", chinaIPv4File)
			checkResults = append(checkResults, struct {
				name     string
				category string
				passed   bool
				error    error
			}{"IPv4中国大陆路由", "中国大陆", false, fmt.Errorf("文件不存在")})
		}

		fmt.Println(strings.Repeat("-", 60))

		// 检查IPv6中国大陆路由
		if _, err := os.Stat(chinaIPv6File); err == nil {
			fmt.Printf("正在检查IPv6中国大陆路由: %s\n", chinaIPv6File)
			passed, err := validator.CheckChinaRoutes(chinaIPv6File)
			checkResults = append(checkResults, struct {
				name     string
				category string
				passed   bool
				error    error
			}{"IPv6中国大陆路由", "中国大陆", passed, err})

			if passed {
				fmt.Printf("✅ IPv6中国大陆路由检查通过\n")
			} else if err != nil {
				fmt.Printf("❌ IPv6中国大陆路由检查出错: %v\n", err)
			} else {
				fmt.Printf("⚠️  IPv6中国大陆路由检查未完全通过\n")
			}
		} else {
			fmt.Printf("⚠️  IPv6中国大陆路由文件不存在: %s\n", chinaIPv6File)
			checkResults = append(checkResults, struct {
				name     string
				category string
				passed   bool
				error    error
			}{"IPv6中国大陆路由", "中国大陆", false, fmt.Errorf("文件不存在")})
		}

		fmt.Println(strings.Repeat("-", 60))
	}

	// 检查非中国大陆路由
	if checkNonChina {
		fmt.Println("🔍 检查非中国大陆路由...")

		birdIPv4File := outputDir + "bird_v4.conf"
		birdIPv6File := outputDir + "bird_v6.conf"

		// 检查IPv4非中国大陆路由
		if _, err := os.Stat(birdIPv4File); err == nil {
			fmt.Printf("正在检查IPv4非中国大陆路由: %s\n", birdIPv4File)
			passed := checkConfigFile(birdIPv4File, dbPath, samples, verbose)
			checkResults = append(checkResults, struct {
				name     string
				category string
				passed   bool
				error    error
			}{"IPv4非中国大陆路由", "非中国大陆", passed, nil})

			if passed {
				fmt.Printf("✅ IPv4非中国大陆路由检查通过\n")
			} else {
				fmt.Printf("❌ IPv4非中国大陆路由检查失败\n")
			}
		} else {
			fmt.Printf("⚠️  IPv4非中国大陆路由文件不存在: %s\n", birdIPv4File)
			checkResults = append(checkResults, struct {
				name     string
				category string
				passed   bool
				error    error
			}{"IPv4非中国大陆路由", "非中国大陆", false, fmt.Errorf("文件不存在")})
		}

		fmt.Println(strings.Repeat("-", 60))

		// 检查IPv6非中国大陆路由
		if _, err := os.Stat(birdIPv6File); err == nil {
			fmt.Printf("正在检查IPv6非中国大陆路由: %s\n", birdIPv6File)
			passed := checkConfigFile(birdIPv6File, dbPath, samples, verbose)
			checkResults = append(checkResults, struct {
				name     string
				category string
				passed   bool
				error    error
			}{"IPv6非中国大陆路由", "非中国大陆", passed, nil})

			if passed {
				fmt.Printf("✅ IPv6非中国大陆路由检查通过\n")
			} else {
				fmt.Printf("❌ IPv6非中国大陆路由检查失败\n")
			}
		} else {
			fmt.Printf("⚠️  IPv6非中国大陆路由文件不存在: %s\n", birdIPv6File)
			checkResults = append(checkResults, struct {
				name     string
				category string
				passed   bool
				error    error
			}{"IPv6非中国大陆路由", "非中国大陆", false, fmt.Errorf("文件不存在")})
		}

		fmt.Println(strings.Repeat("-", 60))
	}

	// 生成检查总结报告
	fmt.Println("\n" + strings.Repeat("=", 80))
	fmt.Println("检查总结报告")
	fmt.Println(strings.Repeat("=", 80))

	allPassed := true
	passedCount := 0
	totalCount := len(checkResults)

	fmt.Printf("检查时间: %s\n", time.Now().Format("2006-01-02 15:04:05"))
	fmt.Printf("总检查项目: %d\n\n", totalCount)

	// 按类别分组显示结果
	chinaResults := []string{}
	nonChinaResults := []string{}

	for _, result := range checkResults {
		status := "❌ 失败"
		if result.passed {
			status = "✅ 通过"
			passedCount++
		} else {
			allPassed = false
		}

		resultLine := fmt.Sprintf("  %s: %s", result.name, status)
		if result.error != nil {
			resultLine += fmt.Sprintf(" (%s)", result.error.Error())
		}

		if result.category == "中国大陆" {
			chinaResults = append(chinaResults, resultLine)
		} else {
			nonChinaResults = append(nonChinaResults, resultLine)
		}
	}

	if len(chinaResults) > 0 {
		fmt.Println("中国大陆路由检查结果:")
		for _, result := range chinaResults {
			fmt.Println(result)
		}
		fmt.Println()
	}

	if len(nonChinaResults) > 0 {
		fmt.Println("非中国大陆路由检查结果:")
		for _, result := range nonChinaResults {
			fmt.Println(result)
		}
		fmt.Println()
	}

	fmt.Printf("总体结果: %d/%d 通过 (%.1f%%)\n",
		passedCount, totalCount, float64(passedCount)*100/float64(totalCount))

	fmt.Println(strings.Repeat("=", 80))

	if allPassed {
		fmt.Println("🎉 所有检查项目都通过了！")
		fmt.Println("✅ 路由配置验证成功")
	} else {
		fmt.Printf("⚠️  %d/%d 项检查失败\n", totalCount-passedCount, totalCount)
		fmt.Println("❌ 路由配置验证失败，请检查上述报告")
		os.Exit(1)
	}
}

func checkConfigFile(configPath, dbPath string, samples int, verbose bool) bool {
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

	// 执行检查
	passed := validator.CheckCIDRs(cidrs)

	// 获取检查结果
	if passed {
		fmt.Printf("  ✅ CIDR检查完成\n")
		return true
	} else {
		fmt.Printf("  ❌ CIDR检查失败\n")
		return false
	}
}
