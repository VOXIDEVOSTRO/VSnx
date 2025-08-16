#include "include.h"

/*==============================================================================================================
  SIMPLE SYSTEM CLOCK - MINIMAL IMPLEMENTATION
================================================================================================================*/

// Initialize system clock
void init_system_clock (void) {
    println("CLOCK: Initializing simple system clock");
    
    system_ticks = 0;
    uptime_seconds = 0;
    clock_initialized = 1;
    
    println("CLOCK: Simple system clock initialized");
}

// Update system clock (called from timer interrupt)
void update_system_clock (void) {
    if (!clock_initialized) return;
    
    system_ticks++;
    
    // Update seconds every 1000 ticks (assuming 1000 Hz timer)
    if ((system_ticks % 1000) == 0) {
        uptime_seconds++;
    }
}

// Get uptime in seconds
uint32_t get_uptime_seconds (void) {
    return uptime_seconds;
}

// Simple uptime display
void show_uptime (void) {
    uint32_t seconds = uptime_seconds;
    uint32_t minutes = seconds / 60;
    uint32_t hours = minutes / 60;
    uint32_t days = hours / 24;
    
    // Display format: "Uptime: 0d 00:00:05"
    print("Uptime: ");
    
    // Days
    char day_str[8];
    day_str[0] = '0' + (days % 10);
    day_str[1] = 'd';
    day_str[2] = ' ';
    day_str[3] = '\0';
    print(day_str);
    
    // Hours
    char hour_str[8];
    hour_str[0] = '0' + ((hours % 24) / 10);
    hour_str[1] = '0' + ((hours % 24) % 10);
    hour_str[2] = ':';
    hour_str[3] = '\0';
    print(hour_str);
    
    // Minutes
    char min_str[8];
    min_str[0] = '0' + ((minutes % 60) / 10);
    min_str[1] = '0' + ((minutes % 60) % 10);
    min_str[2] = ':';
    min_str[3] = '\0';
    print(min_str);
    
    // Seconds
    char sec_str[8];
    sec_str[0] = '0' + ((seconds % 60) / 10);
    sec_str[1] = '0' + ((seconds % 60) % 10);
    sec_str[2] = '\0';
    println(sec_str);
}

void timer_interrupt_handler (void) {
    update_system_clock();
}
