// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright 2020 Daniel Wagner <dwagner@suse.de>
 * Copyright 2020 John Kacur <jkacur@redhat.com>
 */

#include <sys/types.h>
#include <unistd.h>
#include <errno.h>
#include <sched.h>
#include <pthread.h>

#include "rt-error.h"
#include "rt-numa.h"

/*
 * numa_available() must be called before any other calls to the numa library
 * returns 1 if numa is available, or 0 if numa is not available
 */
int numa_initialize(void)
{
	static int is_initialized; // Only call numa_available once
	static int numa;

	if (is_initialized == 1)
		return numa;

	if (numa_available() != -1)
		numa = 1;

	is_initialized = 1;

	return numa;
}

int get_available_cpus(struct bitmask *cpumask)
{
	cpu_set_t cpuset;
	int ret;

	if (cpumask)
		return numa_bitmask_weight(cpumask);

	CPU_ZERO(&cpuset);

	ret = sched_getaffinity(0, sizeof(cpu_set_t), &cpuset);
	if (ret < 0)
		fatal("sched_getaffinity failed: %m\n");

	return CPU_COUNT(&cpuset);
}

int cpu_for_thread_sp(int thread_num, int max_cpus, struct bitmask *cpumask)
{
	unsigned int m, cpu, i, num_cpus;

	num_cpus = numa_bitmask_weight(cpumask);

	if (num_cpus == 0)
		fatal("No allowable cpus to run on\n");

	m = thread_num % num_cpus;

	/* there are num_cpus bits set, we want position of m'th one */
	for (i = 0, cpu = 0; i < max_cpus; i++)
	{
		if (numa_bitmask_isbitset(cpumask, i))
		{
			if (cpu == m)
				return i;
			cpu++;
		}
	}
	warn("Bug in cpu mask handling code.\n");
	return 0;
}

/* cpu_for_thread AFFINITY_USEALL */
int cpu_for_thread_ua(int thread_num, int max_cpus)
{
	int res, num_cpus, i, m, cpu;
	cpu_set_t cpuset;

	CPU_ZERO(&cpuset);

	res = sched_getaffinity(0, sizeof(cpu_set_t), &cpuset);
	if (res != 0)
		fatal("sched_getaffinity failed: %s\n", strerror(res));

	num_cpus = CPU_COUNT(&cpuset);
	m = thread_num % num_cpus;

	for (i = 0, cpu = 0; i < max_cpus; i++)
	{
		if (CPU_ISSET(i, &cpuset))
		{
			if (cpu == m)
				return i;
			cpu++;
		}
	}

	warn("Bug in cpu mask handling code.\n");
	return 0;
}

/*
 * After this function is called, affinity_mask is the intersection of
 * the user supplied affinity mask and the affinity mask from the run
 * time environment
 */
static void use_current_cpuset(int max_cpus, struct bitmask *cpumask)
{
	struct bitmask *curmask;
	int i;

	/*
		函数的作用是分配一个位掩码，其大小等于内核的 CPU 掩码（内核类型 cpumask_t）的大小
		换句话说，它足够大，可以表示 NR_CPUS 个 CPU
	*/
	curmask = numa_allocate_cpumask();
	/*
		将当前进程的 CPU 亲和性存储在该位掩码
	*/
	numa_sched_getaffinity(getpid(), curmask);

	/*
	 * Clear bits that are not set in both the cpuset from the
	 * environment, and in the user specified affinity.
	 */
	/*
		遍历所有线程：
			清除没有在 环境的cpuset和用户指定的亲和性中设置的位（cpu核心）
	*/
	for (i = 0; i < max_cpus; i++)
	{
		/*
			<numa_bitmask_isbitset>
			功能：返回位掩码中指定位的值。如果 i 值大于位图的大小，则返回0
			<numa_bitmask_clearbit>
			功能：将位掩码中的指定位设置为0。如果 i 值大于位掩码的大小，则不执行任何操作（并且不返回任何错误）
		*/
		if ((!numa_bitmask_isbitset(cpumask, i)) ||
			(!numa_bitmask_isbitset(curmask, i)))
			numa_bitmask_clearbit(cpumask, i);
	}
	/*
		解除分配bmp指向的位掩码结构和位掩码的内存,尝试释放此位掩码两次是错误的 [重复释放].
	*/
	numa_bitmask_free(curmask);
}

/*
	参数：
		str: --affinity=1-2 参数的值 "1-2"
		max_cpus : 系统中的 CPU 核心数
		bitmask :
*/
int parse_cpumask(char *str, int max_cpus, struct bitmask **cpumask)
{
	struct bitmask *mask;

	/*
		<numa_parse_cpustring_all>

		函数定义： <numa.h>
		功能：将 CPU 的 ASCII 列表转换为位掩码;
		如：
			str: "1-2, 4-5" [表示CPU 1, 2, 4, 5]
			返回值：位掩码结构体
	*/
	mask = numa_parse_cpustring_all(str);
	if (!mask)
		return -ENOMEM;
	/*
		<numa_bitmask_weight>

		功能：返回位掩码结构体中掩码的位数
	*/
	if (numa_bitmask_weight(mask) == 0)
	{
		/*
			功能：释放位掩码结构体的内存
		*/
		numa_bitmask_free(mask);
		*cpumask = NULL;
		return 0;
	}

	// 如果参数值中包含 ！|| + 则特殊处理
	if (strchr(str, '!') != NULL || strchr(str, '+') != NULL)
		use_current_cpuset(max_cpus, mask);
	*cpumask = mask;

	return 0;
}
