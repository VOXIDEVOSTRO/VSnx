/*
MIT License

Copyright (c) 2025 Aditya Bansal

Permission is hereby granted, free of charge, to any person obtaining 
a copy of this software and associated documentation files (the "Software"), 
to deal in the Software without restriction, including without limitation the 
rights to use, copy, modify, merge, publish, distribute, sublicense, 
and/or sell copies of the Software, and to permit persons to whom 
the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be 
included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, 
EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, 
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, 
WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/

// vwm.c - VOSTROX Window Manager
#include <stdint.h>
#include <stddef.h>
#include "../os/kernel/syscall.h"

typedef struct {
    int x, y, width, height;
    int active;
    int dragging;
    int resizing;
    int resize_edge;
    int drag_offset_x, drag_offset_y;
    int target_x, target_y;
    int z_order;
    int maximized;  // NEW: Is window maximized?
    int restore_x, restore_y, restore_width, restore_height;  // NEW: Original size/position
    char title[32];
    uint32_t color;
} window_t;

#define MAX_WINDOWS 16 //just to prevent flooding for now
#define WINDOW_TITLE_HEIGHT 20
#define WINDOW_BORDER_WIDTH 1

static window_t windows[MAX_WINDOWS];
static int window_count = 0;
static int active_window = -1;

#define COLOR_DESKTOP       0x004080
#define COLOR_WINDOW        0xFFFFFF  // White window body
#define COLOR_TITLEBAR      0xC0C0C0  // Light gray titlebar
#define COLOR_TITLEBAR_TEXT 0x000000  // Black text
#define COLOR_BORDER_LIGHT  0xFFFFFF  // White highlight
#define COLOR_BORDER_DARK   0x808080  // Dark gray shadow
#define COLOR_CLOSE_BTN     0xC0C0C0  // Gray close button
#define COLOR_CLOSE_X       0x000000  // Black X

#define RESIZE_NONE   0
#define RESIZE_RIGHT  1
#define RESIZE_BOTTOM 2
#define RESIZE_CORNER 3
#define RESIZE_BORDER 8  // Resize handle size

// Add resize tracking
static int is_resizing = 0;

//entry here
void _start() {
    sys_declare_function("SYSTEM", "println", 1);
    sys_call_function("VWM: window manager testing starting", 0, 0, 0, 0, 0);
	// Load wallpaper on startup
	debug_print("VWM: Attempting to load wallpaper");
	load_wallpaper_bmp("/HELLO.BMP");
    create_window(100, 100, 200, 150, "test1", 0x000000);
    create_window(200, 200, 250, 180, "test2", 0xFFFFFF);
    create_window(300, 150, 180, 120, "test3", 0x80FF80);
    draw_desktop();
    
    int last_left_button = 0;
    int last_mouse_x = -1, last_mouse_y = -1;
    
    while (1) {
        // Single mouse poll per loop - avoid race conditions
        int mouse_x = get_mouse_x();
        int mouse_y = get_mouse_y();
        
        sys_declare_function("SYSTEM", "get_left_button_state", 0);
        int left_button = sys_call_function(0, 0, 0, 0, 0, 0);
        
        if (left_button && !last_left_button) {
            handle_mouse_click(mouse_x, mouse_y);
        } else if (!left_button && last_left_button) {
    		if (active_window >= 0) {
    		    windows[active_window].dragging = 0;
    		    windows[active_window].resizing = 0;  // NEW: stop resizing
    		    draw_desktop();
    		}
        } else if (left_button && active_window >= 0) {
		    if (windows[active_window].dragging) {
		        handle_mouse_drag(mouse_x, mouse_y);
		    } else if (windows[active_window].resizing) {  // NEW: handle resizing
		        handle_mouse_resize(mouse_x, mouse_y);
		    }
		}
        last_left_button = left_button;
        last_mouse_x = mouse_x;
        last_mouse_y = mouse_y;
    }
}

// Simple 5x7 font - only letters and numbers
static const uint8_t font_5x7[][7] = {
    // 0 (48)
    {0x0E, 0x11, 0x13, 0x15, 0x19, 0x11, 0x0E},
    // 1 (49)
    {0x04, 0x0C, 0x04, 0x04, 0x04, 0x04, 0x0E},
    // 2 (50)
    {0x0E, 0x11, 0x01, 0x02, 0x04, 0x08, 0x1F},
    // 3 (51)
    {0x1F, 0x02, 0x04, 0x02, 0x01, 0x11, 0x0E},
    // 4 (52)
    {0x02, 0x06, 0x0A, 0x12, 0x1F, 0x02, 0x02},
    // 5 (53)
    {0x1F, 0x10, 0x1E, 0x01, 0x01, 0x11, 0x0E},
    // 6 (54)
    {0x06, 0x08, 0x10, 0x1E, 0x11, 0x11, 0x0E},
    // 7 (55)
    {0x1F, 0x01, 0x02, 0x04, 0x08, 0x08, 0x08},
    // 8 (56)
    {0x0E, 0x11, 0x11, 0x0E, 0x11, 0x11, 0x0E},
    // 9 (57)
    {0x0E, 0x11, 0x11, 0x0F, 0x01, 0x02, 0x0C},
    // A (65) - index 10
    {0x0E, 0x11, 0x11, 0x11, 0x1F, 0x11, 0x11},
    // B (66)
    {0x1E, 0x11, 0x11, 0x1E, 0x11, 0x11, 0x1E},
    // C (67)
    {0x0E, 0x11, 0x10, 0x10, 0x10, 0x11, 0x0E},
    // D (68)
    {0x1C, 0x12, 0x11, 0x11, 0x11, 0x12, 0x1C},
    // E (69)
    {0x1F, 0x10, 0x10, 0x1E, 0x10, 0x10, 0x1F},
    // F (70)
    {0x1F, 0x10, 0x10, 0x1E, 0x10, 0x10, 0x10},
    // G (71)
    {0x0E, 0x11, 0x10, 0x17, 0x11, 0x11, 0x0F},
    // H (72)
    {0x11, 0x11, 0x11, 0x1F, 0x11, 0x11, 0x11},
    // I (73)
    {0x0E, 0x04, 0x04, 0x04, 0x04, 0x04, 0x0E},
    // J (74)
    {0x07, 0x02, 0x02, 0x02, 0x02, 0x12, 0x0C},
    // K (75)
    {0x11, 0x12, 0x14, 0x18, 0x14, 0x12, 0x11},
    // L (76)
    {0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x1F},
    // M (77)
    {0x11, 0x1B, 0x15, 0x15, 0x11, 0x11, 0x11},
    // N (78)
    {0x11, 0x11, 0x19, 0x15, 0x13, 0x11, 0x11},
    // O (79)
    {0x0E, 0x11, 0x11, 0x11, 0x11, 0x11, 0x0E},
    // P (80)
    {0x1E, 0x11, 0x11, 0x1E, 0x10, 0x10, 0x10},
    // Q (81)
    {0x0E, 0x11, 0x11, 0x11, 0x15, 0x12, 0x0D},
    // R (82)
    {0x1E, 0x11, 0x11, 0x1E, 0x14, 0x12, 0x11},
    // S (83)
    {0x0F, 0x10, 0x10, 0x0E, 0x01, 0x01, 0x1E},
    // T (84)
    {0x1F, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04},
    // U (85)
    {0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x0E},
    // V (86)
    {0x11, 0x11, 0x11, 0x11, 0x11, 0x0A, 0x04},
    // W (87)
    {0x11, 0x11, 0x11, 0x15, 0x15, 0x1B, 0x11},
    // X (88)
    {0x11, 0x11, 0x0A, 0x04, 0x0A, 0x11, 0x11},
    // Y (89)
    {0x11, 0x11, 0x11, 0x0A, 0x04, 0x04, 0x04},
    // Z (90)
    {0x1F, 0x01, 0x02, 0x04, 0x08, 0x10, 0x1F}
};

void draw_char(int x, int y, char c, uint32_t color) {
    int index = -1;
    
    if (c >= '0' && c <= '9') {
        index = c - '0';  // 0-9
    } else if (c >= 'A' && c <= 'Z') {
        index = c - 'A' + 10;  // A-Z start at index 10
    } else if (c >= 'a' && c <= 'z') {
        index = c - 'a' + 10;  // lowercase = uppercase
    } else {
        return; // Skip unknown characters
    }
    
    const uint8_t* glyph = font_5x7[index];
    
    for (int row = 0; row < 7; row++) {
        uint8_t line = glyph[row];
        for (int col = 0; col < 5; col++) {
            if (line & (1 << (4 - col))) {
                put_pixel(x + col, y + row, color);
            }
        }
    }
}

void draw_text(int x, int y, const char* text, uint32_t color) {
    int px = x;
    for (int i = 0; text[i]; i++) {
        draw_char(px, y, text[i], color);
        px += 6; // 5 pixels + 1 space
    }
}

void put_pixel(int x, int y, uint32_t color) {
    sys_declare_function("SYSTEM", "put_pixel", 3); //function wrapper for call put_picel
    sys_call_function(x, y, color, 0, 0, 0);
}
void draw_rect_pixels(int x, int y, int width, int height, uint32_t color) {
    sys_declare_function("SYSTEM", "draw_rect", 5);
    sys_call_function(x, y, width, height, color, 0);
}

void print_text_at(int x, int y, const char* text, uint32_t color) {
    draw_text(x, y, text, color);
}

int get_resize_edge(window_t* win, int x, int y) {
    int right_edge = (x >= win->x + win->width - RESIZE_BORDER && x <= win->x + win->width);
    int bottom_edge = (y >= win->y + win->height - RESIZE_BORDER && y <= win->y + win->height);
    
    if (right_edge && bottom_edge) return RESIZE_CORNER;
    if (right_edge) return RESIZE_RIGHT;
    if (bottom_edge) return RESIZE_BOTTOM;
    return RESIZE_NONE;
}

void bring_window_to_front(int win_id) {
    if (win_id < 0 || win_id >= window_count) return;
    
    // Find highest z_order
    int max_z = 0;
    for (int i = 0; i < window_count; i++) {
        if (windows[i].active && windows[i].z_order > max_z) {
            max_z = windows[i].z_order;
        }
    }
    
    // Set this window to highest + 1
    windows[win_id].z_order = max_z + 1;
}

// potato looking window
void draw_window_detailed(int win_id) {
    if (win_id < 0 || win_id >= window_count) return;
    window_t* win = &windows[win_id];

    // Outer border - dark gray
    draw_rect_pixels(win->x - 2, win->y - WINDOW_TITLE_HEIGHT - 2, 
                    win->width + 4, win->height + WINDOW_TITLE_HEIGHT + 4, 
                    COLOR_BORDER_DARK);
    
    // Inner border - white highlight
    draw_rect_pixels(win->x - 1, win->y - WINDOW_TITLE_HEIGHT - 1, 
                    win->width + 2, win->height + WINDOW_TITLE_HEIGHT + 2, 
                    COLOR_BORDER_LIGHT);

    // Title bar with gradient effect
    draw_rect_pixels(win->x, win->y - WINDOW_TITLE_HEIGHT, win->width, WINDOW_TITLE_HEIGHT, COLOR_TITLEBAR);
    
    // Title bar top highlight
    draw_rect_pixels(win->x, win->y - WINDOW_TITLE_HEIGHT, win->width, 1, COLOR_BORDER_LIGHT);
    
    // Title bar bottom shadow
    draw_rect_pixels(win->x, win->y - 1, win->width, 1, COLOR_BORDER_DARK);

	// Maximize button - NEW (left of close button)
	int max_x = win->x + win->width - 36;
	int max_y = win->y - WINDOW_TITLE_HEIGHT + 2;	

	// Draw maximize button
	draw_rect_pixels(max_x, max_y, 16, 16, COLOR_CLOSE_BTN);
	draw_rect_pixels(max_x, max_y, 16, 1, COLOR_BORDER_LIGHT);
	draw_rect_pixels(max_x, max_y, 1, 16, COLOR_BORDER_LIGHT);
	draw_rect_pixels(max_x, max_y + 15, 16, 1, COLOR_BORDER_DARK);
	draw_rect_pixels(max_x + 15, max_y, 1, 16, COLOR_BORDER_DARK);	

	// Draw maximize icon (square)
	if (win->maximized) {
	    // Draw restore icon (two overlapping squares)
	    draw_rect_pixels(max_x + 4, max_y + 3, 8, 6, COLOR_BORDER_DARK);
	    draw_rect_pixels(max_x + 5, max_y + 4, 6, 4, COLOR_WINDOW);
	    draw_rect_pixels(max_x + 6, max_y + 5, 6, 6, COLOR_BORDER_DARK);
	    draw_rect_pixels(max_x + 7, max_y + 6, 4, 4, COLOR_WINDOW);
	} else {
	    // Draw maximize icon (single square)
	    draw_rect_pixels(max_x + 4, max_y + 4, 8, 8, COLOR_BORDER_DARK);
	    draw_rect_pixels(max_x + 5, max_y + 5, 6, 6, COLOR_WINDOW);
	}

    // Close button - beveled
    int close_x = win->x + win->width - 18;
    int close_y = win->y - WINDOW_TITLE_HEIGHT + 2;
    
    // Close button background
    draw_rect_pixels(close_x, close_y, 16, 16, COLOR_CLOSE_BTN);
    
    // Close button bevel - light top/left
    draw_rect_pixels(close_x, close_y, 16, 1, COLOR_BORDER_LIGHT);
    draw_rect_pixels(close_x, close_y, 1, 16, COLOR_BORDER_LIGHT);
    
    // Close button bevel - dark bottom/right
    draw_rect_pixels(close_x, close_y + 15, 16, 1, COLOR_BORDER_DARK);
    draw_rect_pixels(close_x + 15, close_y, 1, 16, COLOR_BORDER_DARK);
    
    // Draw X on close button
    for (int i = 0; i < 8; i++) {
        put_pixel(close_x + 4 + i, close_y + 4 + i, COLOR_CLOSE_X);
        put_pixel(close_x + 11 - i, close_y + 4 + i, COLOR_CLOSE_X);
    }

	// Draw window title text
    if (win->title[0] != '\0') {
        int title_x = win->x + 4;
        int title_y = win->y - WINDOW_TITLE_HEIGHT + 4;
        print_text_at(title_x, title_y, win->title, COLOR_TITLEBAR_TEXT);
    }

    // Window content - white background
    draw_rect_pixels(win->x, win->y, win->width, win->height, COLOR_WINDOW);
    
    // Window content inner bevel
    draw_rect_pixels(win->x, win->y, win->width, 1, COLOR_BORDER_DARK);
    draw_rect_pixels(win->x, win->y, 1, win->height, COLOR_BORDER_DARK);
    draw_rect_pixels(win->x, win->y + win->height - 1, win->width, 1, COLOR_BORDER_LIGHT);
    draw_rect_pixels(win->x + win->width - 1, win->y, 1, win->height, COLOR_BORDER_LIGHT);
}

// BMP header structures
typedef struct {
    uint16_t type;
    uint32_t size;
    uint16_t reserved1;
    uint16_t reserved2;
    uint32_t offset;
} __attribute__((packed)) bmp_header_t;

typedef struct {
    uint32_t size;
    int32_t width;
    int32_t height;
    uint16_t planes;
    uint16_t bits_per_pixel;
    uint32_t compression;
    uint32_t image_size;
    int32_t x_pixels_per_meter;
    int32_t y_pixels_per_meter;
    uint32_t colors_used;
    uint32_t colors_important;
} __attribute__((packed)) bmp_info_header_t;

// Wallpaper data
static uint32_t* wallpaper_data = NULL;
static int wallpaper_width = 0;
static int wallpaper_height = 0;

// IPC wrapper for debug printing
void debug_print(const char* msg) {
    sys_declare_function("SYSTEM", "println", 1);
    sys_call_function((uint64_t)msg, 0, 0, 0, 0, 0);
}

// Load BMP wallpaper via SYSTEM IPC with debug
int load_wallpaper_bmp(const char* filename) {
    debug_print("VWM: Starting wallpaper load");
    
    // Open file
    sys_declare_function("SYSTEM", "fs_open", 1);
    int fd = sys_call_function((uint64_t)filename, 0, 0, 0, 0, 0);
    if (fd < 0) {
        debug_print("VWM: Failed to open wallpaper file");
        return -1;
    }
    debug_print("VWM: File opened successfully");
    
    // Read BMP header
    bmp_header_t header;
    sys_declare_function("SYSTEM", "fs_read", 3);
    int header_read = sys_call_function(fd, (uint64_t)&header, sizeof(header), 0, 0, 0);
    if (header_read != sizeof(header)) {
        debug_print("VWM: Failed to read BMP header");
        sys_declare_function("SYSTEM", "fs_close", 1);
        sys_call_function(fd, 0, 0, 0, 0, 0);
        return -1;
    }
    debug_print("VWM: BMP header read");
    
    // Verify BMP signature
    if (header.type != 0x4D42) { // "BM"
        debug_print("VWM: Invalid BMP signature");
        sys_declare_function("SYSTEM", "fs_close", 1);
        sys_call_function(fd, 0, 0, 0, 0, 0);
        return -1;
    }
    debug_print("VWM: BMP signature valid");
    
    // Read info header
    bmp_info_header_t info;
    sys_declare_function("SYSTEM", "fs_read", 3);
    int info_read = sys_call_function(fd, (uint64_t)&info, sizeof(info), 0, 0, 0);
    if (info_read != sizeof(info)) {
        debug_print("VWM: Failed to read BMP info header");
        sys_declare_function("SYSTEM", "fs_close", 1);
        sys_call_function(fd, 0, 0, 0, 0, 0);
        return -1;
    }
    debug_print("VWM: BMP info header read");
    
    // Calculate image size if not provided in BMP
	uint32_t calculated_size = info.image_size;
	if (calculated_size == 0) {
	    // Calculate manually: width * height * bytes_per_pixel, with row padding
	    int row_size = ((info.width * 3 + 3) / 4) * 4; // 4-byte aligned rows
	    calculated_size = row_size * (info.height > 0 ? info.height : -info.height);
	    debug_print("VWM: Calculated image size manually");
	}

	// Validate calculated size
	if (calculated_size == 0 || calculated_size > 16 * 1024 * 1024) {
	    debug_print("VWM: Invalid calculated image size");
	    sys_declare_function("SYSTEM", "fs_close", 1);
	    sys_call_function(fd, 0, 0, 0, 0, 0);
	    return -1;
	}
	debug_print("VWM: Image size valid");

	// Only support 24-bit BMPs
	if (info.bits_per_pixel != 24) {
	    debug_print("VWM: Unsupported BMP format (not 24-bit)");
	    sys_declare_function("SYSTEM", "fs_close", 1);
	    sys_call_function(fd, 0, 0, 0, 0, 0);
	    return -1;
	}
	debug_print("VWM: 24-bit BMP confirmed");

	// Allocate buffer for image data using calculated size
	sys_declare_function("SYSTEM", "user_malloc", 1);
	uint8_t* image_data = (uint8_t*)sys_call_function(calculated_size, 0, 0, 0, 0, 0);
	if (!image_data) {
	    debug_print("VWM: Failed to allocate image buffer");
	    sys_declare_function("SYSTEM", "fs_close", 1);
	    sys_call_function(fd, 0, 0, 0, 0, 0);
	    return -1;
	}
	debug_print("VWM: Image buffer allocated");
    
    // Seek to image data
    sys_declare_function("SYSTEM", "fs_lseek", 3);
    sys_call_function(fd, header.offset, 0, 0, 0, 0);
    debug_print("VWM: Seeked to image data");
    
    // Read image data
    sys_declare_function("SYSTEM", "fs_read", 3);
    int data_read = sys_call_function(fd, (uint64_t)image_data, calculated_size, 0, 0, 0);
    if (data_read != calculated_size) {
        debug_print("VWM: Failed to read image data");
        sys_declare_function("SYSTEM", "user_free", 1);
        sys_call_function((uint64_t)image_data, 0, 0, 0, 0, 0);
        sys_declare_function("SYSTEM", "fs_close", 1);
        sys_call_function(fd, 0, 0, 0, 0, 0);
        return -1;
    }
    debug_print("VWM: Image data read successfully");
    
    // Close file
    sys_declare_function("SYSTEM", "fs_close", 1);
    sys_call_function(fd, 0, 0, 0, 0, 0);
    debug_print("VWM: File closed");
    
    // Free old wallpaper if exists
    if (wallpaper_data) {
        sys_declare_function("SYSTEM", "user_free", 1);
        sys_call_function((uint64_t)wallpaper_data, 0, 0, 0, 0, 0);
        debug_print("VWM: Old wallpaper freed");
    }
    
    // Convert BGR to RGB and store
    wallpaper_width = info.width;
    wallpaper_height = info.height > 0 ? info.height : -info.height;
    debug_print("VWM: Starting BGR to RGB conversion");
    
    // Allocate RGB data buffer - FIXED: only pass size
    sys_declare_function("SYSTEM", "user_malloc", 1);
    wallpaper_data = (uint32_t*)sys_call_function(wallpaper_width * wallpaper_height * 4, 0, 0, 0, 0, 0);
    if (!wallpaper_data) {
        debug_print("VWM: Failed to allocate RGB buffer");
        sys_declare_function("SYSTEM", "user_free", 1);
        sys_call_function((uint64_t)image_data, 0, 0, 0, 0, 0);
        return -1;
    }
    
    // Convert BGR to RGB
    int row_size = ((wallpaper_width * 3 + 3) / 4) * 4;
    for (int y = 0; y < wallpaper_height; y++) {
        for (int x = 0; x < wallpaper_width; x++) {
            int src_y = info.height > 0 ? (wallpaper_height - 1 - y) : y;
            int src_idx = src_y * row_size + x * 3;
            int dst_idx = y * wallpaper_width + x;
            
            uint8_t b = image_data[src_idx];
            uint8_t g = image_data[src_idx + 1];
            uint8_t r = image_data[src_idx + 2];
            
            wallpaper_data[dst_idx] = (r << 16) | (g << 8) | b;
        }
    }
    
    // Free temporary image data
    sys_declare_function("SYSTEM", "user_free", 1);
    sys_call_function((uint64_t)image_data, 0, 0, 0, 0, 0);
    
    debug_print("VWM: Wallpaper loaded successfully");
    return 0;
}

// In vwm.c - optimize existing draw_wallpaper
static uint32_t* wallpaper_cache = NULL;
static int cache_valid = 0;

void draw_wallpaper() {
    if (!wallpaper_data) return;
    
    // Create cache on first use
    if (!wallpaper_cache) {
        sys_declare_function("SYSTEM", "user_malloc", 1);
        wallpaper_cache = (uint32_t*)sys_call_function(1024 * 768 * 4, 0, 0, 0, 0, 0);
        cache_valid = 0;
    }
    
    // Pre-scale wallpaper once
    if (!cache_valid) {
        for (int y = 0; y < 768; y++) {
            for (int x = 0; x < 1024; x++) {
                int src_x = (x * wallpaper_width) / 1024;
                int src_y = (y * wallpaper_height) / 768;
                wallpaper_cache[y * 1024 + x] = wallpaper_data[src_y * wallpaper_width + src_x];
            }
        }
        cache_valid = 1;
    }
    
    // Fast copy from cache
    for (int y = 0; y < 768; y++) {
        for (int x = 0; x < 1024; x++) {
            put_pixel(x, y, wallpaper_cache[y * 1024 + x]);
        }
    }
}

// Add global for tracking window movement
static int is_dragging = 0;

// Optimized wallpaper drawing - only draw specific region
// Fix draw_wallpaper_region to use cache
// Fix draw_wallpaper_region to always use cache
void draw_wallpaper_region(int x, int y, int width, int height) {
    // Ensure cache exists
    if (!wallpaper_cache && wallpaper_data) {
        sys_declare_function("SYSTEM", "user_malloc", 1);
        wallpaper_cache = (uint32_t*)sys_call_function(1024 * 768 * 4, 0, 0, 0, 0, 0);
        if (wallpaper_cache) {
            for (int py = 0; py < 768; py++) {
                for (int px = 0; px < 1024; px++) {
                    int src_x = (px * wallpaper_width) / 1024;
                    int src_y = (py * wallpaper_height) / 768;
                    wallpaper_cache[py * 1024 + px] = wallpaper_data[src_y * wallpaper_width + src_x];
                }
            }
        }
    }
    
    if (!wallpaper_cache) {
        draw_rect_pixels(x, y, width, height, COLOR_DESKTOP);
        return;
    }
    
    // Clamp bounds
    if (x < 0) { width += x; x = 0; }
    if (y < 0) { height += y; y = 0; }
    if (x + width > 1024) width = 1024 - x;
    if (y + height > 768) height = 768 - y;
    
    // Use cached wallpaper
    for (int py = y; py < y + height; py++) {
        for (int px = x; px < x + width; px++) {
            put_pixel(px, py, wallpaper_cache[py * 1024 + px]);
        }
    }
}

// Remove cursor operations from draw_desktop during drag/resize
void draw_desktop() {
    // Only manage cursor if not in active operation
    if (!is_dragging && !is_resizing) {
        sys_declare_function("SYSTEM", "disable_cursor_updates", 0);
        sys_call_function(0, 0, 0, 0, 0, 0);
    }
    
    if (!is_dragging) {
        if (wallpaper_data) {
            draw_wallpaper();
        } else {
            sys_declare_function("SYSTEM", "draw_rect", 5);
            sys_call_function(0, 0, 1024, 768, COLOR_DESKTOP, 0);
        }
    }
    
    for (int z_level = 0; z_level < 1000; z_level++) {
        for (int i = 0; i < window_count; i++) {
            if (windows[i].active && windows[i].z_order == z_level) {
                draw_window_detailed(i);
            }
        }
    }
    
    if (!is_dragging && !is_resizing) {
        sys_declare_function("SYSTEM", "enable_cursor_updates", 0);
        sys_call_function(0, 0, 0, 0, 0, 0);
        
        sys_declare_function("SYSTEM", "renderer_present_mfs", 0);
        sys_call_function(0, 0, 0, 0, 0, 0);
    }
}

// just create a window entry
int create_window(int x, int y, int width, int height, const char* title, uint32_t color) {
    if (window_count >= MAX_WINDOWS) return -1;
    
    window_t* win = &windows[window_count];
    win->x = x;
    win->y = y;
    win->width = width;
    win->height = height;
    win->active = 1;
    win->dragging = 0;
    win->resizing = 0;
    win->resize_edge = RESIZE_NONE;
	win->maximized = 0;
	win->restore_x = x;
	win->restore_y = y;
	win->restore_width = width;
	win->restore_height = height;
    win->z_order = window_count;  // NEW: Set initial Z-order
    win->color = COLOR_WINDOW;
    
    int i = 0;
    while (title[i] && i < 31) {
        win->title[i] = title[i];
        i++;
    }
    win->title[i] = '\0';
    
    active_window = window_count;
    return window_count++;
}

void toggle_maximize_window(int win_id) {
    if (win_id < 0 || win_id >= window_count) return;
    
    window_t* win = &windows[win_id];
    
    // Always disable cursor for fullscreen operations
    sys_declare_function("SYSTEM", "disable_cursor_updates", 0);
    sys_call_function(0, 0, 0, 0, 0, 0);
    
    if (win->maximized) {
        // Restore to original size
        win->x = win->restore_x;
        win->y = win->restore_y;
        win->width = win->restore_width;
        win->height = win->restore_height;
        win->maximized = 0;
    } else {
        // Save current size/position
        win->restore_x = win->x;
        win->restore_y = win->y;
        win->restore_width = win->width;
        win->restore_height = win->height;
        
        // Maximize to full screen
        win->x = 0;
        win->y = WINDOW_TITLE_HEIGHT;
        win->width = 1024;
        win->height = 768 - WINDOW_TITLE_HEIGHT;
        win->maximized = 1;
    }
    
    // Force complete redraw for both maximize and restore
    if (wallpaper_data) {
        draw_wallpaper();
    } else {
        draw_rect_pixels(0, 0, 1024, 768, COLOR_DESKTOP);
    }
    
    // Redraw all windows in Z-order
    for (int z_level = 0; z_level < 1000; z_level++) {
        for (int i = 0; i < window_count; i++) {
            if (windows[i].active && windows[i].z_order == z_level) {
                draw_window_detailed(i);
            }
        }
    }
    
    sys_declare_function("SYSTEM", "enable_cursor_updates", 0);
    sys_call_function(0, 0, 0, 0, 0, 0);
    
    sys_declare_function("SYSTEM", "renderer_present_mfs", 0);
    sys_call_function(0, 0, 0, 0, 0, 0);
}

int get_mouse_x() {
    sys_declare_function("SYSTEM", "get_mouse_x", 0); //get x position of cursor
    return sys_call_function(0, 0, 0, 0, 0, 0);
}

int get_mouse_y() {
    sys_declare_function("SYSTEM", "get_mouse_y", 0); //get y position of cursor
    return sys_call_function(0, 0, 0, 0, 0, 0);
}

// Modify mouse click to set resize flag
void handle_mouse_click(int x, int y) {
    // Find topmost window at click position
    int clicked_window = -1;
    for (int i = window_count - 1; i >= 0; i--) {
        if (!windows[i].active) continue;
        
        window_t* win = &windows[i];
        
        // Check if click is anywhere within window bounds (including titlebar)
        if (x >= win->x - 2 && x <= win->x + win->width + 2 &&
            y >= win->y - WINDOW_TITLE_HEIGHT - 2 && y <= win->y + win->height + 2) {
            clicked_window = i;
            break; // Found topmost window
        }
    }
    
    if (clicked_window == -1) {
        active_window = -1;
        return;
    }
    
    window_t* win = &windows[clicked_window];
    
    // Check maximize button
    if (x >= win->x + win->width - 36 && x <= win->x + win->width - 20 &&
        y >= win->y - WINDOW_TITLE_HEIGHT + 2 && y <= win->y - WINDOW_TITLE_HEIGHT + 18) {
        toggle_maximize_window(clicked_window);
        return;
    }
    
    // Check close button
	if (x >= win->x + win->width - 18 && x <= win->x + win->width - 2 &&
	    y >= win->y - WINDOW_TITLE_HEIGHT + 2 && y <= win->y - WINDOW_TITLE_HEIGHT + 18) {
	    win->active = 0;
		
	    // Force complete redraw when closing window
	    sys_declare_function("SYSTEM", "disable_cursor_updates", 0);
	    sys_call_function(0, 0, 0, 0, 0, 0);
		
	    // Clear entire screen
	    if (wallpaper_data) {
	        draw_wallpaper();
	    } else {
	        draw_rect_pixels(0, 0, 1024, 768, COLOR_DESKTOP);
	    }
	
	    // Redraw all remaining active windows
	    for (int z_level = 0; z_level < 1000; z_level++) {
	        for (int i = 0; i < window_count; i++) {
	            if (windows[i].active && windows[i].z_order == z_level) {
	                draw_window_detailed(i);
	            }
	        }
	    }
	
	    sys_declare_function("SYSTEM", "enable_cursor_updates", 0);
	    sys_call_function(0, 0, 0, 0, 0, 0);
	
	    sys_declare_function("SYSTEM", "renderer_present_mfs", 0);
	    sys_call_function(0, 0, 0, 0, 0, 0);
	
	    return;
	}
    
    // Check resize edges
    int resize_edge = get_resize_edge(win, x, y);
    if (resize_edge != RESIZE_NONE) {
        bring_window_to_front(clicked_window);
        win->resizing = 1;
        win->resize_edge = resize_edge;
        active_window = clicked_window;
        is_resizing = 1;
        return;
    }
    
    // Check titlebar for dragging - ONLY titlebar brings to front
    if (x >= win->x && x <= win->x + win->width - 38 &&
        y >= win->y - WINDOW_TITLE_HEIGHT && y <= win->y) {
        bring_window_to_front(clicked_window);
        win->dragging = 1;
        win->drag_offset_x = x - win->x;
        win->drag_offset_y = y - win->y;
        active_window = clicked_window;
        is_dragging = 1;
        return;
    }
    
    // Window body click - just set active, don't bring to front
    if (x >= win->x && x <= win->x + win->width &&
        y >= win->y && y <= win->y + win->height) {
        active_window = clicked_window;
        // No draw_desktop() call - no visual change
        return;
    }
    
    active_window = -1;
}

// Add throttling variables
static int resize_counter = 0;

// Optimize resize - skip frequent redraws
static int resize_skip_counter = 0;

// Add frame skipping for better performance
static int drag_skip_counter = 0;

void handle_mouse_drag(int x, int y) {
    if (active_window < 0 || !windows[active_window].dragging) return;
    
    window_t* win = &windows[active_window];
    
    // Skip if position hasn't changed
    int new_x = x - win->drag_offset_x;
    int new_y = y - win->drag_offset_y;
    if (new_x == win->x && new_y == win->y) return;
    
    // Calculate old position for cleanup
    int old_x = win->x;
    int old_y = win->y;
    int old_full_x = old_x - 2;
    int old_full_y = old_y - WINDOW_TITLE_HEIGHT - 2;
    int old_full_w = win->width + 4;
    int old_full_h = win->height + WINDOW_TITLE_HEIGHT + 4;
    
    // Update window position
    win->x = new_x;
    win->y = new_y;
    
    // Disable cursor for this operation
    sys_declare_function("SYSTEM", "disable_cursor_updates", 0);
    sys_call_function(0, 0, 0, 0, 0, 0);
    
    // Redraw old position with wallpaper - ALWAYS
    if (wallpaper_cache) {
        draw_wallpaper_region(old_full_x, old_full_y, old_full_w, old_full_h);
    } else {
        draw_rect_pixels(old_full_x, old_full_y, old_full_w, old_full_h, COLOR_DESKTOP);
    }
    
    // Redraw intersecting windows - ALWAYS
    for (int i = 0; i < window_count; i++) {
        if (i == active_window || !windows[i].active) continue;
        
        window_t* other = &windows[i];
        int other_full_x = other->x - 2;
        int other_full_y = other->y - WINDOW_TITLE_HEIGHT - 2;
        int other_full_w = other->width + 4;
        int other_full_h = other->height + WINDOW_TITLE_HEIGHT + 4;
        
        if (!(other_full_x >= old_full_x + old_full_w || 
              other_full_x + other_full_w <= old_full_x ||
              other_full_y >= old_full_y + old_full_h ||
              other_full_y + other_full_h <= old_full_y)) {
            draw_window_detailed(i);
        }
    }
    
    // Draw dragged window at new position - ALWAYS
    draw_window_detailed(active_window);
    
    // Re-enable cursor and present - ALWAYS
    sys_declare_function("SYSTEM", "enable_cursor_updates", 0);
    sys_call_function(0, 0, 0, 0, 0, 0);
    
    sys_declare_function("SYSTEM", "renderer_present_mfs", 0);
    sys_call_function(0, 0, 0, 0, 0, 0);
}

void handle_mouse_resize(int x, int y) {
    if (active_window < 0 || !windows[active_window].resizing) return;
    
    window_t* win = &windows[active_window];
    
    int old_width = win->width;
    int old_height = win->height;
    
    if (win->resize_edge == RESIZE_RIGHT || win->resize_edge == RESIZE_CORNER) {
        int new_width = x - win->x;
        if (new_width > 100) win->width = new_width;
    }
    
    if (win->resize_edge == RESIZE_BOTTOM || win->resize_edge == RESIZE_CORNER) {
        int new_height = y - win->y;
        if (new_height > 50) win->height = new_height;
    }
    
    // Only redraw if size actually changed
    if (win->width != old_width || win->height != old_height) {
        sys_declare_function("SYSTEM", "disable_cursor_updates", 0);
        sys_call_function(0, 0, 0, 0, 0, 0);
        
        // Calculate union of old and new areas
        int min_x = win->x - 2;
        int min_y = win->y - WINDOW_TITLE_HEIGHT - 2;
        int max_width = (old_width > win->width ? old_width : win->width);
        int max_height = (old_height > win->height ? old_height : win->height);
        int clear_w = max_width + 4;
        int clear_h = max_height + WINDOW_TITLE_HEIGHT + 4;
        
        // Clear the entire affected area
        if (wallpaper_cache) {
            draw_wallpaper_region(min_x, min_y, clear_w, clear_h);
        } else {
            draw_rect_pixels(min_x, min_y, clear_w, clear_h, COLOR_DESKTOP);
        }
        
        // Redraw intersecting windows
        for (int i = 0; i < window_count; i++) {
            if (i == active_window || !windows[i].active) continue;
            
            window_t* other = &windows[i];
            int other_x = other->x - 2;
            int other_y = other->y - WINDOW_TITLE_HEIGHT - 2;
            int other_w = other->width + 4;
            int other_h = other->height + WINDOW_TITLE_HEIGHT + 4;
            
            if (!(other_x >= min_x + clear_w || other_x + other_w <= min_x ||
                  other_y >= min_y + clear_h || other_y + other_h <= min_y)) {
                draw_window_detailed(i);
            }
        }
        
        // Draw resized window
        draw_window_detailed(active_window);
        
        sys_declare_function("SYSTEM", "enable_cursor_updates", 0);
        sys_call_function(0, 0, 0, 0, 0, 0);
        
        sys_declare_function("SYSTEM", "renderer_present_mfs", 0);
        sys_call_function(0, 0, 0, 0, 0, 0);
    }
}

void handle_mouse_release() {
    if (active_window >= 0) {
        windows[active_window].dragging = 0;
        windows[active_window].resizing = 0;
        is_dragging = 0;
        is_resizing = 0;
        draw_desktop(); // Final clean redraw
    }
}

//simple string functions
size_t strlen(const char *s) {
    size_t len = 0;
    while (s[len]) len++;
    return len;
}

char* strcpy(char *dest, const char *src) {
    char *d = dest;
    while ((*d++ = *src++));
    return dest;
}

