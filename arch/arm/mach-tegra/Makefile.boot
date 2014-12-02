zreladdr-$(CONFIG_ARCH_TEGRA_2x_SOC)	:= 0x00008000
params_phys-$(CONFIG_ARCH_TEGRA_2x_SOC)	:= 0x00000100
initrd_phys-$(CONFIG_ARCH_TEGRA_2x_SOC)	:= 0x00800000

zreladdr-$(CONFIG_ARCH_TEGRA_3x_SOC)	:= 0x80008000
params_phys-$(CONFIG_ARCH_TEGRA_3x_SOC)	:= 0x80000100
initrd_phys-$(CONFIG_ARCH_TEGRA_3x_SOC)	:= 0x80800000

dtb-$(CONFIG_ARCH_TEGRA_2x_SOC) += tegra20-harmony.dtb
dtb-$(CONFIG_ARCH_TEGRA_2x_SOC) += tegra20-paz00.dtb
dtb-$(CONFIG_ARCH_TEGRA_2x_SOC) += tegra20-seaboard.dtb
dtb-$(CONFIG_ARCH_TEGRA_2x_SOC) += tegra20-trimslice.dtb
dtb-$(CONFIG_ARCH_TEGRA_2x_SOC) += tegra20-ventana.dtb
dtb-$(CONFIG_ARCH_TEGRA_2x_SOC) += tegra20-whistler.dtb
dtb-$(CONFIG_ARCH_TEGRA_3x_SOC) += tegra30-cardhu.dtb
dtb-$(CONFIG_ARCH_TEGRA_3x_SOC) += tegra30-enterprise.dtb
dtb-$(CONFIG_ARCH_TEGRA_3x_SOC) += tegra30-tai.dtb
dtb-$(CONFIG_ARCH_TEGRA_11x_SOC) += tegra114-dalmore.dtb
dtb-$(CONFIG_ARCH_TEGRA_11x_SOC) += tegra114-macallan.dtb
dtb-$(CONFIG_ARCH_TEGRA_11x_SOC) += tegra114-roth.dtb
dtb-$(CONFIG_ARCH_TEGRA_11x_SOC) += tegra114-pluto.dtb
dtb-$(CONFIG_ARCH_TEGRA_11x_SOC) += tegra114-tegratab.dtb
dtb-$(CONFIG_ARCH_TEGRA_3x_SOC) += tegra30-x3.dtb
