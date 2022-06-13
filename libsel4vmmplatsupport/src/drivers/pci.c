/*
 * Copyright 2019, Data61, CSIRO (ABN 41 687 119 230)
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

/* VMM PCI Driver, which manages the host's PCI devices, and handles guest OS PCI config space
 * read & writes.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <sel4/sel4.h>
#include <pci/pci.h>
#include <pci/helper.h>

#include <sel4vmmplatsupport/drivers/pci.h>
#include <sel4vmmplatsupport/drivers/pci_helper.h>


int vmm_pci_init(vmm_pci_space_t **space)
{
    vmm_pci_space_t *pci_space = (typeof(pci_space))calloc(1, sizeof(*pci_space));
    if (!pci_space) {
        ZF_LOGE("Failed to calloc %u bytes of memory for pci space", sizeof(*pci_space));
        return -1;
    }

    for (int i = 0; i < ARRAY_SIZE(pci_space->bus); i++) {
        vmm_pci_device_t *dev = &pci_space->bus[i];
        for (int j = 0; j < ARRAY_SIZE(dev->func); j++) {
            dev->func[j] = NULL;
        }
    }
    pci_space->conf_port_addr = 0;
    /* Define the initial PCI bridge */
    vmm_pci_device_def_t *bridge = calloc(1, sizeof(*bridge));
    if (!bridge) {
        ZF_LOGE("Failed to calloc memory for pci bridge");
        return -1;
    }
    define_pci_host_bridge(bridge);
    *space = pci_space;
    return vmm_pci_add_entry(pci_space, (vmm_pci_entry_t) {
        .cookie = bridge,
        .ioread = vmm_pci_mem_device_read,
        .iowrite = vmm_pci_entry_ignore_write
    }, NULL);
}

int vmm_pci_add_entry(vmm_pci_space_t *space, vmm_pci_entry_t entry, vmm_pci_address_t *addr)
{
    /* Find empty dev */
    for (int i = 0; i < ARRAY_SIZE(space->bus); i++) {
        vmm_pci_device_t* dev = &space->bus[i];
        vmm_pci_entry_t **slot = &dev->func[0];

        if (!*slot) {
            /* Allocate an entry */
            *slot = calloc(1, sizeof(entry));
            /* populate entry */
            **slot = entry;
            /* Report addr if requested */
            if (addr) {
                *addr = (vmm_pci_address_t) {
                    .bus = 0, .dev = i, .fun = 0
                };
            }
            ZF_LOGI("Adding virtual PCI device at %02x:%02x.%d", 0, i, 0);
            return 0;
        }
    }
    ZF_LOGE("No free device slot on bus 0 to add virtual pci device");
    return -1;
}

void make_addr_reg_from_config(uint32_t conf, vmm_pci_address_t *addr, uint8_t *reg)
{
    addr->bus = (conf >> 16) & MASK(8);
    addr->dev = (conf >> 11) & MASK(5);
    addr->fun = (conf >> 8) & MASK(3);
    *reg = conf & MASK(8);
}

vmm_pci_entry_t *find_device(vmm_pci_space_t *self, vmm_pci_address_t addr)
{
    if (addr.bus != 0 || addr.dev >= ARRAY_SIZE(self->bus)) {
        return NULL;
    }

    vmm_pci_device_t *dev = &self->bus[addr.dev];

    if (addr.fun >= ARRAY_SIZE(dev->func)) {
        return NULL;
    }

    return dev->func[addr.fun];
}
