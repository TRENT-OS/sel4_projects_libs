/*
 * Copyright 2019, Data61, CSIRO (ABN 41 687 119 230)
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>

#include <elf/elf.h>
#include <vka/capops.h>
#include <cpio/cpio.h>
#include <sel4utils/sel4_zf_logif.h>

#include <sel4vm/guest_vm.h>
#include <sel4vm/guest_memory.h>
#include <sel4vm/guest_ram.h>

#include <sel4vmmplatsupport/guest_image.h>

#define UIMAGE_MAGIC 0x56190527
#define ZIMAGE_MAGIC 0x016F2818
#define DTB_MAGIC    0xedfe0dd0
#define INITRD_GZ_MAGIC 0x8b1f

typedef struct {
    uint32_t magic;
} uimg_hdr_t;

typedef struct {
    uint32_t magic;
#if 0
    uint32_t size;
    uint32_t off_dt_struct;
    uint32_t off_dt_strings;
    uint32_t off_mem_rsvmap;
    uint32_t version;
    uint32_t comp_version;
    uint32_t boot_cpuid;
    uint32_t size_dt_strings;
    uint32_t size_dt_struct;
#endif
} dtb_hdr_t;

typedef struct {
    uint16_t magic;
    uint8_t compression;
    uint8_t flags;
} initrd_gz_hdr_t;

typedef struct {
    uint32_t code[9];
    uint32_t magic;
    uint32_t start;
    uint32_t end;
} zimage_hdr_t;

typedef union {
    uimg_hdr_t uimg_hdr;
    dtb_hdr_t dtb_hdr;
    initrd_gz_hdr_t initrd_gz_hdr;
    zimage_hdr_t zimage_hdr;
    Elf64_Ehdr *header;
} generic_hdr_t;

static bool is_uImage(void const *buffer)
{
    uimg_hdr_t const *hdr = (uimg_hdr_t const*)buffer;
    return (hdr->magic == UIMAGE_MAGIC);
}

static bool is_zImage(void const *buffer)
{
    zimage_hdr_t const *hdr = (zimage_hdr_t const *)buffer;
    return (hdr->magic == ZIMAGE_MAGIC);
}

static bool is_dtb(void const *buffer)
{
    dtb_hdr_t const *hdr = (dtb_hdr_t const *)buffer;
    return (hdr->magic == DTB_MAGIC);
}

static bool is_initrd(void const *buffer)
{
    initrd_gz_hdr_t const *hdr = (initrd_gz_hdr_t const *)buffer;
    /* We currently only support initrd files in the gzip format */
    return (hdr->magic == INITRD_GZ_MAGIC);
}

static int guest_write_address(vm_t *vm, uintptr_t paddr, void *vaddr, size_t size, size_t offset, void *cookie)
{
    int fd = *((int *)cookie);

    /* Load the image */
    size_t len = read(fd, vaddr, size);
    if (len != size) {
        ZF_LOGE("Bytes read from the file server (%d) don't match expected length (%d)", len, size);
        return -1;
    }

    if (vm->mem.clean_cache) {
        seL4_CPtr cap = vspace_get_cap(&vm->mem.vmm_vspace, vaddr);
        if (cap == seL4_CapNull) {
            /* Not sure how we would get here, something has gone pretty wrong */
            ZF_LOGE("Failed to get vmm cap for vaddr: %p", vaddr);
            return -1;
        }
        int error = seL4_ARM_Page_CleanInvalidate_Data(cap, 0, PAGE_SIZE_4K);
        ZF_LOGF_IFERR(error, "seL4_ARM_Page_CleanInvalidate_Data failed");
    }
    return 0;
}

static int vm_load_image(vm_t *vm, const char *name, bool is_kernel,
                         uintptr_t load_addr, guest_image_t *image)
{
    assert(image);

    int err;

    int fd = open(name, 0);
    if (fd == -1) {
        ZF_LOGE("Error: Unable to open image '%s'", name);
        return -1;
    }

    size_t file_size = lseek(fd, 0, SEEK_END);
    lseek(fd, 0, SEEK_SET);

    generic_hdr_t header = {0};
    size_t len = read(fd, &header, sizeof(header));

    if (len != sizeof(header)) {
        ZF_LOGE("Could not read len. File is likely corrupt");
        close(fd);
        return -1;
    }

    if (0 == elf_check_magic((void*)&header)) {
        /* so far, this is unsupported */
        ZF_LOGE("Error: ELF format is unsupported");
        close(fd);
        return -1;

    } else if (is_zImage((void*)&header)) {
        if (!is_kernel) {
            ZF_LOGE("Error: zImage format is supported for kernel only");
            close(fd);
            return -1;
        }
        /* zImage is used for 32-bit Linux kernels only. */
        uintptr_t start = header.zimage_hdr.start;
        if (start != 0) {
            load_addr = start;
        }

    } else if (is_uImage((void*)&header)) {
        /* so far, this is unsupported */
        ZF_LOGE("Error: uImage ELF format is unsupported");
        return -1; /* unsupported */

    } else if (is_dtb((void*)&header)) {
        if (is_kernel) {
            ZF_LOGE("Error: DTB file is no valis kernel");
            close(fd);
            return -1;
        }

    } else if (is_initrd((void*)&header)) {
        if (is_kernel) {
            close(fd);
            return -1;
        }

    } else {
        /* binary */
    }

    lseek(fd, 0, SEEK_SET);
    vm_ram_mark_allocated(vm, load_addr, ROUND_UP(file_size, PAGE_SIZE_4K));
    err = vm_ram_touch(vm, load_addr, file_size, guest_write_address, (void *)&fd);
    close(fd);
    if (err) {
        ZF_LOGE("Error: Failed to load '%s' (%d)", name, err);
        close(fd);
        return -1;
    }

    image->load_paddr = load_addr;
    image->size = file_size;
    return 0;
}


int vm_load_guest_kernel(vm_t *vm, const char *kernel_name,
                         uintptr_t load_address, size_t alignment,
                         guest_kernel_image_t *guest_kernel_image)
{
    if (!guest_kernel_image) {
        ZF_LOGE("Invalid guest_kernel_image object");
        return -1;
    }

    int err = vm_load_image(vm, kernel_name, true, load_address,
                            &(guest_kernel_image->kernel_image));
    if (err) {
        ZF_LOGE("Kernel image loading failed (%d)", err);
        return -1;
    }

    return 0;
}

int vm_load_guest_module(vm_t *vm, const char *module_name,
                         uintptr_t load_address, size_t alignment,
                         guest_image_t *guest_image)
{
    if (!guest_image) {
        ZF_LOGE("Invalid guest_image_t object");
        return -1;
    }

    int err = vm_load_image(vm, module_name, false, load_address, guest_image);
    if (err) {
        ZF_LOGE("Module image loading failed (%d)", err);
        return -1;
    }

    return 0;
}
