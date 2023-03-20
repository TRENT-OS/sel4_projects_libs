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

static int get_guest_image_type(const char *image_name, enum img_type *image_type, generic_hdr_t *header)
{
    int fd = open(image_name, 0);
    if (fd == -1) {
        ZF_LOGE("Error: Unable to open image \'%s\'", image_name);
        return -1;
    }

    size_t len = read(fd, header, sizeof(*header));
    close(fd);

    if (len != sizeof(*header)) {
        ZF_LOGE("Could not read len. File is likely corrupt");
        return -1;
    }

    *image_type = (elf_check_magic((void*)header) == 0) ? IMG_ELF
                  : (is_zImage((void*)header)) ? IMG_ZIMAGE
                  : (is_uImage((void*)header)) ? IMG_UIMAGE
                  : (is_dtb((void*)header)) ? IMG_DTB
                  : (is_initrd((void*)header)) ? IMG_INITRD_GZ
                  : IMG_BIN;

    return 0;
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

static int load_image(vm_t *vm, const char *image_name, uintptr_t load_addr, size_t *resulting_image_size)
{
    int fd;
    int error;

    fd = open(image_name, 0);
    if (fd == -1) {
        ZF_LOGE("Error: Unable to find image \'%s\'", image_name);
        return -1;
    }

    size_t file_size = lseek(fd, 0, SEEK_END);
    lseek(fd, 0, SEEK_SET);

    if (0 == file_size) {
        ZF_LOGE("Error: \'%s\' has zero size", image_name);
        return -1;
    }

    vm_ram_mark_allocated(vm, load_addr, ROUND_UP(file_size, PAGE_SIZE_4K));
    error = vm_ram_touch(vm, load_addr, file_size, guest_write_address, (void *)&fd);
    if (error) {
        ZF_LOGE("Error: Failed to load \'%s\'", image_name);
        close(fd);
        return -1;
    }

    *resulting_image_size = file_size;
    close(fd);
    return 0;
}

int vm_load_guest_kernel(vm_t *vm, const char *kernel_name, uintptr_t load_address, size_t alignment,
                         guest_kernel_image_t *guest_kernel_image)
{
    int err;

    if (!guest_kernel_image) {
        ZF_LOGE("Invalid guest_image_t object");
        return -1;
    }

    /* Determine the load address */
    uintptr_t load_addr;
    enum img_type ret_file_type;
    generic_hdr_t header = {0};
    err = get_guest_image_type(kernel_name, &ret_file_type, &header);
    if (err) {
        return -1;
    }
    switch (ret_file_type) {
    case IMG_BIN:
        load_addr = vm->entry;
        break;
    case IMG_ZIMAGE:
        /* zImage is used for 32-bit Linux kernels only. */
        load_addr = ((zimage_hdr_t *)(&header))->start;
        if (0 == load_addr) {
            load_addr = vm->entry;
        }
        break;
    default:
        ZF_LOGE("Error: Unknown kernel image format for '%s'", kernel_image_name);
        return -1;
    }

    size_t len = 0;
    err = load_image(vm, kernel_name, load_addr, &len);
    if (err) {
        return -1;
    }

    guest_kernel_image->kernel_image.load_paddr = load_addr;
    guest_kernel_image->kernel_image.size = len;
    return 0;
}

int vm_load_guest_module(vm_t *vm, const char *module_name, uintptr_t load_address, size_t alignment,
                         guest_image_t *guest_image)
{
    int err;

    if (!guest_image) {
        ZF_LOGE("Invalid guest_image_t object");
        return -1;
    }

    /* Determine the load address */
    uintptr_t load_addr;
    generic_hdr_t header = {0};
    enum img_type ret_file_type;
    err = get_guest_image_type(module_name, &ret_file_type, &header);
    if (err) {
        return 0;
    }
    switch (ret_file_type) {
    case IMG_DTB:
    case IMG_INITRD_GZ:
        load_addr = load_address;
        break;
    default:
        ZF_LOGE("Error: Unknown module image format for '%s'", image_name);
        return 0;
    }

    size_t len = 0;
    err = load_image(vm, module_name, load_addr, &len);
    if (err) {
        return 0;
    }

    guest_image->load_paddr = load_addr;
    guest_image->size = len;
    return 0;
}
