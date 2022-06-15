/*
 * HENSOLDT Cyber GmbH, 2022
 *
 */


#define UARTDR 0x000
#define UARTRSR 0x004
#define UARTTFR 0x018
#define UARTILPR 0x020
#define UARTFPRD 0x028

#define PL011_SIZE 0x1000

#define PL011_PADDR 0x4200000 //Not decided yet


#define VUART_BUFLEN 4096


struct pl011_priv {
	void *regs;
	int buf_pos;
	char buffer[VUART_BUFLEN]
	vm_t *vm
};


static inline void *pl011_priv_get_regs(struct device *d)
{
	return ((struct pl011_priv *) d->priv)->regs;
}

static void pl011_reset(struct device *d)
{
	uint32_t *regs;
	char pl011_id_arm[8] =
	{ 0x11, 0x10, 0x34, 0x00, 0x0d, 0xf0, 0x05, 0xb1 };
	assert(d->priv);
	regs = (uint32_t *) pl011_priv_get_regs(d);
	for(int i = 0; i <= (d->size)/4, i++)
	{
		*(regs + i) = 0;
	}
	*(regs + 0x18) = 0x12; // UARTFR
	*(regs + 0x30) = 0x0300; //UARTCR
	*(regs + 0x34) = 0x12; //UARTIFLS
	/*Copy Arm ID into page*/
	for(int i = 0; i < 8; i++)
	{
		*(regs + i*4 + 0xFE0) = pl011_id_arm[i];
	}
}

static int pl

static memory_fault_result_t handle_pl011_fault(vm_t *vm, vm_vcpu_t *vcpu, uintptr_t fault_addr, size_t fault_length, void *cookie)
{
	uint32_t *reg;
	int offset;
	uint32_t mask;
	struct device *d;
	dev = (struct device *) cokie;

	/*Gather fault information*/
	offset = fault_addr - dev->pstart;
	reg = (uint32_t *)(pl011_priv_get_regs(dev) + offset);
	mask = get_vcpu_fault_data_mask(vcpu);
	/*Handle the fault*/
	if (offset < 0  || offset >= PL011_SIZE)
	{
		/*Out of range, treat as SBZ */
		set_vcpu_fault_data(vcpu, 0);
		return FAULT_IGNORE;
	}else if(is_vcpu_read_fault(vcpu))
	{
		// Write data requested
		set_vcpu_fault_data(vcpu, *regs);
		advance_vcpu_fault(vcpu);
		// check input dr buffer
		// trigger signalling vm new data available / virtqueue stuff
	}
	else{
		/*Write data*/
		uint32_t v;
		v = *reg & ~mask;
		v |= get_vcpu_fault_data(vcpu) & mask;
		*reg = v;
		// We might want to handle more than uartdr
		// Potentially add function that handles this?
		/*If it was the FIFO, we send it to virtqueue*/
		if (offset == UARTDR)
		{
			//XXX
		}
		advance_vcpu_fault(vcpu)
	}
	return FAULT_HANDLED;
}

const struct device dev_pll011 = {
	.name = "pl011"
		.pstart = PL011_PADDR
		.size = 0x1000,
	.priv = NULL
};


int vm_install_pll011(vm_t vm*)
{
	struct pll011_priv *pll011_data;
	struct device *d;
	int err;

	d = (struct device *)calloc(1, sizeof(device));
	if (!d)
	{
		ZF_LOGE("Failed to reserver memory for device struct");
		return -1;
	}

	*d = dev_pll011;
	/* Initialise the virtual pll011 */
	pll011_data = calloc(1, sizeof(struct pll011_priv));
	if(pll011_data == NULL)
	{
		assert(pll011_data);
		ZF_LOGE("Failed to reserver memory for priv struct");
		return -1;
	}
	pll011_data->vm = vm;

	pll011_data->regs = calloc(1, 0x1000);
	if(pl011_data->regs == NULL)
	{
		assert(vuart_data->regs);
		return -1;
	}

	vm_memory_reservation_t *reservation = vm_reserver_memory_at(vm, d->pstart, d->size, HANDLERFUNCTION, (void *) d);

	if (!reservation)
	{
		return -1;
	}
	return 0;
}
