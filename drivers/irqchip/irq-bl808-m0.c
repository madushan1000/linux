#define pr_fmt(fmt) "m0ic: " fmt
#include <linux/io.h>
#include <linux/irq.h>
#include <linux/irqchip.h>
#include <linux/irqdomain.h>
#include <linux/of_address.h>
#include <linux/of_device.h>

// #define GLB_BASE         ((uint32_t)0x20000000)
// #define GLB_CORE_CFG16_OFFSET (0x50)  //status 0
// #define GLB_CORE_CFG17_OFFSET (0x54)  //status 1
// #define GLB_CORE_CFG18_OFFSET (0x58)  //mask 0
// #define GLB_CORE_CFG19_OFFSET (0x5C)  //mask 1
// #define GLB_CORE_CFG20_OFFSET (0x60)  //clear 0
// #define GLB_CORE_CFG21_OFFSET (0x64)  //clear 1

#define STATUS0_OFFSET 0x0
#define STATUS1_OFFSET 0x4
#define MASK0_OFFSET   0x8
#define MASK1_OFFSET   0xC
#define CLEAR0_OFFSET  0x10
#define CLEAR1_OFFSET  0x14

struct m0ic_priv {
	struct irq_domain *irq_domain;
	void __iomem *regs;
};

void m0ic_chip_set_bit(long nr, volatile unsigned long * addr){
    unsigned long tmp;
    tmp = readl(addr);
    tmp |= BIT(nr);
    writel(tmp, addr);
}

void m0ic_chip_clear_bit(long nr, volatile unsigned long * addr){
    unsigned long tmp;
    tmp = readl(addr);
    tmp &= ~BIT(nr);
    writel(tmp, addr);
}

static void m0ic_irq_mask(struct irq_data *d)
{
    unsigned long tmp;
    struct m0ic_priv *priv = irq_data_get_irq_chip_data(d);

    if (d->hwirq < 32) {
        m0ic_chip_set_bit(d->hwirq, priv->regs + MASK0_OFFSET);
        // tmp = readl(priv->regs + MASK0_OFFSET);
        // tmp |= BIT(d->hwirq);
        // writel(tmp, priv->regs + MASK0_OFFSET);
    } else {
        m0ic_chip_set_bit(d->hwirq, priv->regs + MASK1_OFFSET);
        // tmp = readl(priv->regs + MASK1_OFFSET);
        // tmp |= BIT(d->hwirq - 32);
        // writel(tmp, priv->regs + MASK1_OFFSET);
    }
}

static void m0ic_irq_unmask(struct irq_data *d)
{
    unsigned long tmp;
    struct m0ic_priv *priv = irq_data_get_irq_chip_data(d);

    if (d->hwirq < 32) {
        m0ic_chip_clear_bit(d->hwirq, priv->regs + MASK0_OFFSET);
        // tmp = readl(priv->regs + MASK0_OFFSET);
        // tmp &= ~BIT(d->hwirq);
        // writel(tmp, priv->regs + MASK0_OFFSET);
    } else {
        m0ic_chip_clear_bit(d->hwirq, priv->regs + MASK1_OFFSET);
        // tmp = readl(priv->regs + MASK1_OFFSET);
        // tmp &= ~BIT(d->hwirq - 32);
        // writel(tmp, priv->regs + MASK1_OFFSET);
    }
}
static void m0ic_irq_eoi(struct irq_data *d)
{
}

static struct irq_chip m0ic_chip = {
	.name = "BFLB M0 INTC",
	.irq_mask = m0ic_irq_mask,
	.irq_unmask = m0ic_irq_unmask,
    .irq_eoi = m0ic_irq_eoi,
};

// static int m0ic_domain_map(struct irq_domain *d, unsigned int irq,
// 				 irq_hw_number_t hwirq)
// {
// 	irq_set_percpu_devid(irq);
// 	irq_domain_set_info(d, irq, hwirq, &m0ic_chip, d->host_data,
// 			    handle_percpu_devid_irq, NULL, NULL);

// 	return 0;
// }

static int m0ic_domain_alloc(struct irq_domain *domain, unsigned int virq,
				unsigned int nr_irqs, void *arg)
{
    struct irq_fwspec *fwspec = arg;
	struct irq_fwspec parent_fwspec;
    int ret;
	unsigned int i, type;
	unsigned long hwirq = 0;
	struct m0ic_priv *priv = domain->host_data;

    ret = irq_domain_translate_onecell(domain, arg, &hwirq, &type);
    pr_info("m0ic_domain_alloc virq %d, nr_irqs %d, ret: %d, hwirq %d\n", virq, nr_irqs, ret, hwirq);
    if (ret)
		return ret;

    for (i = 0; i < nr_irqs; i++) {
        irq_domain_set_hwirq_and_chip(domain, virq + i, hwirq + i, &m0ic_chip, priv);
		// irq_domain_set_info(domain, virq + i, hwirq + i, &m0ic_chip,
		// 			priv, handle_edge_irq, NULL, NULL);
	}

	parent_fwspec.fwnode = domain->parent->fwnode;
    parent_fwspec.param_count = 2;
    parent_fwspec.param[0] = hwirq;
    parent_fwspec.param[1] = IRQ_TYPE_LEVEL_HIGH;
	return irq_domain_alloc_irqs_parent(domain, virq, nr_irqs,
					    &parent_fwspec);
}

static const struct irq_domain_ops m0ic_irqdomain_ops = {
	// .map	= m0ic_domain_map,
	// .xlate	= irq_domain_xlate_onecell,
	.translate	= irq_domain_translate_onecell,
	.alloc		= m0ic_domain_alloc,
	.free		= irq_domain_free_irqs_common,
};

// static const struct of_device_id m0ic_matches[] = {
// 	{ .compatible = "bflb,m0ic" },
// 	{ }
// };

static irqreturn_t m0ic_handle_irq(int irq, void *data){
    struct m0ic_priv *priv = data;    
    unsigned long firing0, firing1;
    int pos;
    // pr_info("got irq STATUS0_OFFSET, %x, STATUS1_OFFSET %x, MASK0_OFFSET %x, MASK1_OFFSET %x,  CLEAR0_OFFSET %x, CLEAR1_OFFSET %x\n", 
    // readl(priv->regs + STATUS0_OFFSET), 
    // readl(priv->regs + STATUS1_OFFSET), 
    // readl(priv->regs + MASK0_OFFSET), 
    // readl(priv->regs + MASK1_OFFSET),
    // readl(priv->regs + CLEAR0_OFFSET),
    // readl(priv->regs + CLEAR1_OFFSET));

    firing0 = readl(priv->regs + STATUS0_OFFSET); //& readl(priv->regs + MASK0_OFFSET);
    firing1 = readl(priv->regs + STATUS1_OFFSET); //& readl(priv->regs + MASK1_OFFSET);

    for_each_set_bit(pos, &firing0, 32) {
        m0ic_chip_set_bit(pos, priv->regs + CLEAR0_OFFSET);
		generic_handle_domain_irq(priv->irq_domain, pos);
    }
    for_each_set_bit(pos, &firing1, 32) {
        m0ic_chip_set_bit(pos, priv->regs + CLEAR1_OFFSET);
		generic_handle_domain_irq(priv->irq_domain, pos);
    }

    // pr_info("2got irq STATUS0_OFFSET, %x, STATUS1_OFFSET %x, MASK0_OFFSET %x, MASK1_OFFSET %x,  CLEAR0_OFFSET %x, CLEAR1_OFFSET %x\n", readl(priv->regs + STATUS0_OFFSET), readl(priv->regs + STATUS1_OFFSET), readl(priv->regs + MASK0_OFFSET), readl(priv->regs + MASK1_OFFSET) ,readl(priv->regs + CLEAR0_OFFSET) ,readl(priv->regs + CLEAR1_OFFSET));

    return IRQ_HANDLED;
}

static int __init bflb_m0ic_init(struct device_node *node,
				   struct device_node *parent)
{
    struct irq_domain *parent_domain, *domain;
    struct m0ic_priv *priv;
	int error = 0, irq;
    pr_info("m0ic init\n");
    if (!parent) {
		pr_err("%pOF: no parent, giving up\n", node);
		return -ENODEV;
	}
    pr_info("parent found\n");

	parent_domain = irq_find_host(parent);
	if (!parent_domain) {
		pr_err("%pOF: unable to obtain parent domain\n", node);
		return -ENXIO;
	}
    pr_info("parent domain found\n");

    priv = kzalloc(sizeof(*priv), GFP_KERNEL);
	if (!priv)
		return -ENOMEM;

    pr_info("priv allocated\n");

    priv->regs = of_iomap(node, 0);
    if (!priv->regs) {
		error = -EIO;
		goto out_free_priv;
    }

    irq = irq_of_parse_and_map(node, 0);
	if (irq < 0) {
		error = irq;
        goto out_iounmap;
    }

    pr_info("regs allocated\n");

    priv->irq_domain = irq_domain_add_hierarchy(parent_domain, 0, 64, node, &m0ic_irqdomain_ops, priv);
	if (!priv->irq_domain) {
        pr_err("%pOF: unable to allocate irq domain\n", node);
        error = -ENOMEM;
		goto out_free_irq;
    }
    pr_info("irqdomain allocated\n");

    if (request_irq(irq, m0ic_handle_irq, IRQF_NO_THREAD, "cascade", priv))
		pr_err("Failed to register cascade interrupt\n");

    writel(0xffffffff, priv->regs + MASK0_OFFSET);
    writel(0xffffffff, priv->regs + MASK1_OFFSET);
    writel(0xffffffff, priv->regs + CLEAR0_OFFSET);
    writel(0xffffffff, priv->regs + CLEAR1_OFFSET);

    return 0;

out_free_irq:
    free_irq(NULL, irq);
out_iounmap:
	iounmap(priv->regs);
out_free_priv:
	kfree(priv);
	return error;
}

IRQCHIP_DECLARE(bflb_m0ic, "bflb,m0ic", bflb_m0ic_init);