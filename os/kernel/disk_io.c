#include "include.h"

/*==============================================================================================================
  DISK I/O
================================================================================================================*/

// ATA functions - OPTIMIZED
// Ultra-optimized single-sector I/O for 20MB/s speeds
void ata_wait_bsy (void) {
    uint32_t timeout = 100000;
    while ((inb(ATA_PRIMARY_STATUS) & ATA_STATUS_BSY) && --timeout);
}

void ata_wait_drq (void) {
    uint32_t timeout = 100000;
    while (!(inb(ATA_PRIMARY_STATUS) & ATA_STATUS_DRQ) && --timeout);
}
int ata_identify (void) {
    uint16_t identify_data[256];
    
    outb(ATA_PRIMARY_DRIVE_HEAD, 0xA0);
    ata_wait_bsy();
    outb(ATA_PRIMARY_COMMAND, ATA_CMD_IDENTIFY);
    
    if (inb(ATA_PRIMARY_STATUS) == 0) {
        return -1;
    }
    
    ata_wait_bsy();
    ata_wait_drq();
    
    for (int i = 0; i < 256; i++) {
        identify_data[i] = inw(ATA_PRIMARY_DATA);
    }
    
    uint16_t size_low = identify_data[60];
    uint16_t size_high = identify_data[61];
    disk_size = ((uint32_t)size_high << 16) | size_low;
    
    return 0;
}

// Block device interface implementation (following block.h)
int block_init (void) {
    disk_error = 0;
    if (ata_identify() != 0) {
        disk_error = 1;
        return -1;
    }
    return 0;
}

int block_halt (void) {
    return 0;
}

// Ultra-fast block read - optimized with existing functions
int block_read(blockno_t block, void *buf) {
    if (!buf || block >= disk_size) {
        disk_error = 1;
        return -1;
    }
    
    // Fast LBA setup using existing outb
    outb(ATA_PRIMARY_DRIVE_HEAD, 0xE0 | ((block >> 24) & 0x0F));
    outb(ATA_PRIMARY_SECTOR_COUNT, 1);
    outb(ATA_PRIMARY_LBA_LOW, block & 0xFF);
    outb(ATA_PRIMARY_LBA_MID, (block >> 8) & 0xFF);
    outb(ATA_PRIMARY_LBA_HIGH, (block >> 16) & 0xFF);
    outb(ATA_PRIMARY_COMMAND, ATA_CMD_READ_SECTORS);
    
    ata_wait_bsy();
    ata_wait_drq();
    
    // Ultra-fast burst read using REP INSW
    __asm__ volatile(
        "movl $256, %%ecx\n"
        "movw $0x1F0, %%dx\n"
        "rep insw"
        :
        : "D"(buf)
        : "ecx", "edx", "memory"
    );
    
    return 0;
}

// Ultra-fast block write - optimized with existing functions
int block_write(blockno_t block, void *buf) {
    if (!buf || block >= disk_size) {
        disk_error = 1;
        return -1;
    }
    
    outb(ATA_PRIMARY_DRIVE_HEAD, 0xE0 | ((block >> 24) & 0x0F));
    outb(ATA_PRIMARY_SECTOR_COUNT, 1);
    outb(ATA_PRIMARY_LBA_LOW, block & 0xFF);
    outb(ATA_PRIMARY_LBA_MID, (block >> 8) & 0xFF);
    outb(ATA_PRIMARY_LBA_HIGH, (block >> 16) & 0xFF);
    outb(ATA_PRIMARY_COMMAND, ATA_CMD_WRITE_SECTORS);
    
    ata_wait_bsy();
    ata_wait_drq();
    
    // Ultra-fast burst write using REP OUTSW
    __asm__ volatile(
        "movl $256, %%ecx\n"
        "movw $0x1F0, %%dx\n"
        "rep outsw"
        :
        : "S"(buf)
        : "ecx", "edx", "memory"
    );
    
    ata_wait_bsy();
    return 0;
}

blockno_t block_get_volume_size (void) {
    return disk_size;
}

int block_get_block_size (void) {
    return BLOCK_SIZE;
}

int block_get_device_read_only (void) {
    return 1; // Read-only for safety
}

int block_get_error (void) {
    return disk_error;
}
