#define pr_fmt(fmt) "m0ic: " fmt
#include <linux/io.h>
#include <linux/irq.h>
#include <linux/irqchip.h>
#include <linux/irqdomain.h>
#include <linux/of_address.h>
#include <linux/of_device.h>

#define STATUS0_OFFSET 0x0
#define STATUS1_OFFSET 0x4
#define MASK0_OFFSET   0x8
#define MASK1_OFFSET   0xC
#define CLEAR0_OFFSET  0x10
#define CLEAR1_OFFSET  0x14

struct bflb_m0ic_priv {
	struct irq_domain *irq_domain;
	void __iomem *regs;
};

void bflb_m0ic_chip_set_bit(long nr, volatile unsigned long * addr){
    unsigned long tmp;
    tmp = readl(addr);
    tmp |= BIT(nr);
    writel(tmp, addr);
}

void bflb_m0ic_chip_clear_bit(long nr, volatile unsigned long * addr){
    unsigned long tmp;
    tmp = readl(addr);
    tmp &= ~BIT(nr);
    writel(tmp, addr);
}

static void bflb_m0ic_irq_mask(struct irq_data *d)
{
    struct bflb_m0ic_priv *priv = irq_data_get_irq_chip_data(d);
    if (d->hwirq < 32) {
        bflb_m0ic_chip_set_bit(d->hwirq, priv->regs + MASK0_OFFSET);
    } else {
        bflb_m0ic_chip_set_bit(d->hwirq, priv->regs + MASK1_OFFSET);
    }
}

static void bflb_m0ic_irq_unmask(struct irq_data *d)
{
    struct bflb_m0ic_priv *priv = irq_data_get_irq_chip_data(d);
    if (d->hwirq < 32) {
        bflb_m0ic_chip_clear_bit(d->hwirq, priv->regs + MASK0_OFFSET);
    } else {
        bflb_m0ic_chip_clear_bit(d->hwirq, priv->regs + MASK1_OFFSET);
    }
}
static void bflb_m0ic_irq_eoi(struct irq_data *d)
{
}

static struct irq_chip bflb_m0ic_chip = {
	.name = "BFLB M0 INTC",
	.irq_mask = bflb_m0ic_irq_mask,
	.irq_unmask = bflb_m0ic_irq_unmask,
    .irq_eoi = bflb_m0ic_irq_eoi,
};

static int bflb_m0ic_domain_alloc(struct irq_domain *domain, unsigned int virq,
				unsigned int nr_irqs, void *arg)
{
    struct irq_fwspec *fwspec = arg;
	struct irq_fwspec parent_fwspec;
    int ret;
	unsigned int i, type;
	unsigned long hwirq = 0;
	struct bflb_m0ic_priv *priv = domain->host_data;

    ret = irq_domain_translate_onecell(domain, arg, &hwirq, &type);
    if (ret)
		return ret;

    for (i = 0; i < nr_irqs; i++) {
        irq_domain_set_hwirq_and_chip(domain, virq + i, hwirq + i, &bflb_m0ic_chip, priv);
	}

	parent_fwspec.fwnode = domain->parent->fwnode;
    parent_fwspec.param_count = 2;
    parent_fwspec.param[0] = hwirq;
    parent_fwspec.param[1] = IRQ_TYPE_LEVEL_HIGH;
	return irq_domain_alloc_irqs_parent(domain, virq, nr_irqs,
					    &parent_fwspec);
}

static const struct irq_domain_ops bflb_m0ic_irqdomain_ops = {
	.translate	= irq_domain_translate_onecell,
	.alloc		= bflb_m0ic_domain_alloc,
	.free		= irq_domain_free_irqs_common,
};

static irqreturn_t bflb_m0ic_handle_irq(int irq, void *data){
    struct bflb_m0ic_priv *priv = data;
    unsigned long firing0, firing1;
    int pos;
    // pr_info("got irq STATUS0_OFFSET, %x, STATUS1_OFFSET %x, MASK0_OFFSET %x, MASK1_OFFSET %x,  CLEAR0_OFFSET %x, CLEAR1_OFFSET %x\n", 
    // readl(priv->regs + STATUS0_OFFSET), 
    // readl(priv->regs + STATUS1_OFFSET), 
    // readl(priv->regs + MASK0_OFFSET), 
    // readl(priv->regs + MASK1_OFFSET),
    // readl(priv->regs + CLEAR0_OFFSET),
    // readl(priv->regs + CLEAR1_OFFSET));

    firing0 = readl(priv->regs + STATUS0_OFFSET);
    firing1 = readl(priv->regs + STATUS1_OFFSET);

    for_each_set_bit(pos, &firing0, 32) {
        bflb_m0ic_chip_set_bit(pos, priv->regs + CLEAR0_OFFSET);
		generic_handle_domain_irq(priv->irq_domain, pos);
    }
    for_each_set_bit(pos, &firing1, 32) {
        bflb_m0ic_chip_set_bit(pos, priv->regs + CLEAR1_OFFSET);
		generic_handle_domain_irq(priv->irq_domain, pos);
    }

    // pr_info("2got irq STATUS0_OFFSET, %x, STATUS1_OFFSET %x, MASK0_OFFSET %x, MASK1_OFFSET %x,  CLEAR0_OFFSET %x, CLEAR1_OFFSET %x\n", readl(priv->regs + STATUS0_OFFSET), readl(priv->regs + STATUS1_OFFSET), readl(priv->regs + MASK0_OFFSET), readl(priv->regs + MASK1_OFFSET) ,readl(priv->regs + CLEAR0_OFFSET) ,readl(priv->regs + CLEAR1_OFFSET));

    return IRQ_HANDLED;
}

static int __init bflb_m0ic_init(struct device_node *node,
				   struct device_node *parent)
{
    struct irq_domain *parent_domain, *domain;
    struct bflb_m0ic_priv *priv;
	int error = 0, irq;
    if (!parent) {
		pr_err("%pOF: no parent, giving up\n", node);
		return -ENODEV;
	}

	parent_domain = irq_find_host(parent);
	if (!parent_domain) {
		pr_err("%pOF: unable to obtain parent domain\n", node);
		return -ENXIO;
	}

    priv = kzalloc(sizeof(*priv), GFP_KERNEL);
	if (!priv)
		return -ENOMEM;

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

    priv->irq_domain = irq_domain_add_hierarchy(parent_domain, 0, 64, node, &bflb_m0ic_irqdomain_ops, priv);
	if (!priv->irq_domain) {
        pr_err("%pOF: unable to allocate irq domain\n", node);
        error = -ENOMEM;
		goto out_free_irq;
    }

    if (request_irq(irq, bflb_m0ic_handle_irq, IRQF_NO_THREAD, "BFLB m0ic", priv))
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
