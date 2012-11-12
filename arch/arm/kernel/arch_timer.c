/*
 *  linux/arch/arm/kernel/arch_timer.c
 *
 *  Copyright (C) 2011 ARM Ltd.
 *  All Rights Reserved
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */
#include <linux/init.h>
#include <linux/types.h>

#include <asm/delay.h>
#include <asm/sched_clock.h>

#include <clocksource/arm_arch_timer.h>

static unsigned long arch_timer_read_counter_long(void)
{
	return arch_timer_read_counter();
}

static u32 arch_timer_read_counter_u32(void)
{
	return arch_timer_read_counter();
}

static struct delay_timer arch_delay_timer;

static void __init arch_timer_delay_timer_register(void)
{
	/* Use the architected timer for the delay loop. */
	arch_delay_timer.read_current_timer = arch_timer_read_counter_long;
	arch_delay_timer.freq = arch_timer_get_rate();
	register_current_timer_delay(&arch_delay_timer);
}

int __init arch_timer_of_register(void)
{
	int ret;

	ret = arch_timer_init();
	if (ret)
		return ret;

	arch_timer_delay_timer_register();

	return 0;
}

int __init arch_timer_sched_clock_init(void)
{
	if (arch_timer_get_rate() == 0)
		return -ENXIO;

	setup_sched_clock(arch_timer_read_counter_u32,
			  32, arch_timer_get_rate());
	return 0;
}
