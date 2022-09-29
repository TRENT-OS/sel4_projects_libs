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

struct dtb_hdr {
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
};

struct initrd_gz_hdr {
    uint16_t magic;
    uint8_t compression;
    uint8_t flags;
};

struct zimage_hdr {
    uint32_t code[9];
    uint32_t magic;
    uint32_t start;
    uint32_t end;
};

static int is_uImage(void *file)
{
    uint32_t magic = UIMAGE_MAGIC;
    return memcmp(file, &magic, sizeof(magic));
}

static int is_zImage(void *file)
{
    struct zimage_hdr *hdr;
    hdr = (struct zimage_hdr *)file;
    return hdr->magic != ZIMAGE_MAGIC;
}

static int is_dtb(void *file)
{
    struct dtb_hdr *hdr;
    hdr = (struct dtb_hdr *)file;
    return hdr->magic != DTB_MAGIC;
}

static int is_initrd(void *file)
{
    /* We currently only support initrd files in the gzip format */
    struct initrd_gz_hdr *hdr;
    hdr = (struct initrd_gz_hdr *)file;
    return hdr->magic != INITRD_GZ_MAGIC;
}

enum img_type image_get_type(void *file)
{
    if (elf_check_magic(file) == 0) {
        return IMG_ELF;
    } else if (is_zImage(file) == 0) {
        return IMG_ZIMAGE;
    } else if (is_uImage(file) == 0) {
        return IMG_UIMAGE;
    } else if (is_dtb(file) == 0) {
        return IMG_DTB;
    } else if (is_initrd(file) == 0) {
        return IMG_INITRD_GZ;
    } else {
        return IMG_BIN;
    }
}

uintptr_t zImage_get_load_address(void *file, uintptr_t ram_base)
{
    struct zimage_hdr *hdr;
    hdr = (struct zimage_hdr *)file;
    if (hdr->start == 0) {
        return ram_base + 0x8000;
    } else {
        return hdr->start;
    }
    return 0;
}

static int get_guest_image_type(const char *image_name, enum img_type *image_type, Elf64_Ehdr *header)
{
    int fd;
    uintptr_t load_addr;
    fd = open(image_name, 0);
    if (fd == -1) {
        ZF_LOGE("Error: Unable to open image \'%s\'", image_name);
        return -1;
    }

    size_t len = read(fd, header, sizeof(*header));
    if (len != sizeof(*header)) {
        ZF_LOGE("Could not read len. File is likely corrupt");
        close(fd);
        return -1;
    }
    *image_type = image_get_type(header);
    close(fd);
    return 0;
}

static uint32_t src_crc32 = 0;
static uint32_t dst_crc32 = 0;
/// compute CRC32 (half-byte algoritm)
uint32_t crc32_halfbyte(const void* data, size_t length, uint32_t previousCrc32)
{
  uint32_t crc = ~previousCrc32; // same as previousCrc32 ^ 0xFFFFFFFF
  const uint8_t* current = (const uint8_t*) data;

  /// look-up table for half-byte, same as crc32Lookup[0][16*i]
  static const uint32_t Crc32Lookup16[16] =
  {
    0x00000000,0x1DB71064,0x3B6E20C8,0x26D930AC,0x76DC4190,0x6B6B51F4,0x4DB26158,0x5005713C,
    0xEDB88320,0xF00F9344,0xD6D6A3E8,0xCB61B38C,0x9B64C2B0,0x86D3D2D4,0xA00AE278,0xBDBDF21C
  };

  while (length-- != 0)
  {
    crc = Crc32Lookup16[(crc ^  *current      ) & 0x0F] ^ (crc >> 4);
    crc = Crc32Lookup16[(crc ^ (*current >> 4)) & 0x0F] ^ (crc >> 4);
    current++;
  }

  return ~crc; // same as crc ^ 0xFFFFFFFF
}

static int guest_write_address(vm_t *vm, uintptr_t paddr, void *vaddr, size_t size, size_t offset, void *cookie)
{

    //ZF_LOGE("guest_write_address vaddr=%p, paddr=%x, size=%x, offset=%x, cookie=%p",vaddr, paddr, size, offset, cookie);
    uint32_t old_src_crc32 = src_crc32;
    uint32_t old_dst_crc32 = dst_crc32;

    src_crc32 = crc32_halfbyte(cookie + offset, size, src_crc32);
    memcpy(vaddr, cookie + offset, size);
    dst_crc32 = crc32_halfbyte(vaddr, size, dst_crc32);

    //ZF_LOGE("guest_write_address src crc32 %x -> %x", old_src_crc32, src_crc32);
    //ZF_LOGE("guest_write_address dst crc32 %x -> %x", old_dst_crc32, dst_crc32);

    if (config_set(CONFIG_PLAT_TX1) || config_set(CONFIG_PLAT_TX2)) {
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

static int load_image(vm_t *vm, const char *image_name, uintptr_t load_addr,  size_t *resulting_image_size)
{
    int fd;
    size_t len;
    int error;

    ZF_LOGE("load_image name=%s, load_addr=%x", image_name, load_addr);
    fd = open(image_name, 0);
    if (fd == -1) {
        ZF_LOGE("Error: Unable to find image \'%s\'", image_name);
        return -1;
    }

    /* Try and load the image 1MiB at a time. Reduce the size by half if
     * there isn't enough memory available.  The total loading time may be
     * faster if a larger buffer is used as it allows for more batching.
     */
    size_t read_size = BIT(20);
    char *buf = malloc(read_size);

    while (buf == NULL) {
        read_size /= 2;
        if (read_size < 4096) {
            ZF_LOGE("Not enough memory for copy buffer");
        }
        buf = malloc(read_size);
    }
    src_crc32 = 0;
    dst_crc32 = 0;
    ZF_LOGE("load_image image=%s, buf=%p, read_size=0x%x", image_name, buf, read_size);

    size_t offset = 0;
    while (1) {
        /* Load the image */
        len = read(fd, buf, read_size);
        if (!len) {
            break;
        }
        vm_ram_mark_allocated(vm, load_addr + offset, len);
        error = vm_ram_touch(vm, load_addr + offset, len, guest_write_address, (void *)buf);
        if (error) {
            ZF_LOGE("Error: Failed to load \'%s\'", image_name);
            close(fd);
            return -1;
        }
        offset += len;
    }

    ZF_LOGE("load_image len=%d, src_crc32=%x, dst_crc32=%x", offset, src_crc32, dst_crc32);
    free(buf);
    *resulting_image_size = offset;
    close(fd);
    return 0;
}

static void *load_guest_kernel_image(vm_t *vm, const char *kernel_image_name, uintptr_t load_base_addr,
                                     size_t *image_size)
{
    int err;
    uintptr_t load_addr;
    enum img_type ret_file_type;
    Elf64_Ehdr header = {0};
    err = get_guest_image_type(kernel_image_name, &ret_file_type, &header);
    if (err) {
        return NULL;
    }
    /* Determine the load address */
    switch (ret_file_type) {
    case IMG_BIN:
        if (config_set(CONFIG_PLAT_TX1) || config_set(CONFIG_PLAT_TX2) || config_set(CONFIG_PLAT_QEMU_ARM_VIRT)
            || config_set(CONFIG_PLAT_ODROIDC2) || config_set(CONFIG_PLAT_RPI4) || config_set(CONFIG_PLAT_BCM2711)) {
            /* This is likely an aarch64/aarch32 linux difference */
            load_addr = load_base_addr + 0x80000;
        } else {
            load_addr = load_base_addr + 0x8000;
        }
        break;
    case IMG_ZIMAGE:
        load_addr = zImage_get_load_address(&header, load_base_addr);
        break;
    default:
        ZF_LOGE("Error: Unknown Linux image format for \'%s\'", kernel_image_name);
        return NULL;
    }

    err = load_image(vm, kernel_image_name, load_addr, image_size);
    if (err) {
        return NULL;
    }
    return (void *)load_addr;
}

static void *load_guest_module_image(vm_t *vm, const char *image_name, uintptr_t load_base_addr, size_t *image_size)
{
    int err;
    uintptr_t load_addr;
    enum img_type ret_file_type;
    Elf64_Ehdr header = {0};
    err = get_guest_image_type(image_name, &ret_file_type, &header);
    if (err) {
        return NULL;
    }
    /* Determine the load address */
    switch (ret_file_type) {
    case IMG_DTB:
    case IMG_INITRD_GZ:
        load_addr = load_base_addr;
        break;
    default:
        ZF_LOGE("Error: Unknown Linux image format for \'%s\'", image_name);
        return NULL;
    }
    err = load_image(vm, image_name, load_addr, image_size);
    if (err) {
        return NULL;
    }
    return (void *)load_addr;
}

int vm_load_guest_kernel(vm_t *vm, const char *kernel_name, uintptr_t load_address, size_t alignment,
                         guest_kernel_image_t *guest_kernel_image)
{
    void *load_addr;
    size_t kernel_len;
    if (!guest_kernel_image) {
        ZF_LOGE("Invalid guest_image_t object");
        return -1;
    }
    load_addr = load_guest_kernel_image(vm, kernel_name, load_address, &kernel_len);
    if (!load_addr) {
        return -1;
    }
    guest_kernel_image->kernel_image.load_paddr = (uintptr_t)load_addr;
    guest_kernel_image->kernel_image.size = kernel_len;
    return 0;
}

int vm_load_guest_module(vm_t *vm, const char *module_name, uintptr_t load_address, size_t alignment,
                         guest_image_t *guest_image)
{
    void *load_addr;
    size_t module_len;

    if (!guest_image) {
        ZF_LOGE("Invalid guest_image_t object");
        return -1;
    }

    load_addr = load_guest_module_image(vm, module_name, load_address, &module_len);
    if (!load_addr) {
        return -1;
    }

    guest_image->load_paddr = (uintptr_t)load_addr;
    guest_image->size = module_len;
    return 0;
}
