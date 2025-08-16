#include "include.h"

/*==============================================================================================================
  GRAPHICS GFX
================================================================================================================*/
void parse_multiboot2(uint64_t mb2_addr) {
    uint32_t total_size = *(uint32_t*)(uintptr_t)mb2_addr;
    struct multiboot_tag* tag = (struct multiboot_tag*)(uintptr_t)(mb2_addr + 8);
    serial_write("Parsing Multiboot\n");

    while ((uintptr_t)tag < mb2_addr + total_size) {
        serial_write("A\n");
        char tag_type_msg[16] = "tag=";
        tag_type_msg[4] = '0' + (tag->type % 10);
        tag_type_msg[5] = '\n';
        tag_type_msg[6] = 0;
        serial_write(tag_type_msg);
        char tag_size_msg[16] = "size=";
        tag_size_msg[5] = '0' + (tag->size % 10);
        tag_size_msg[6] = '\n';
        tag_size_msg[7] = 0;
        serial_write(tag_size_msg);

        if (tag->type == MULTIBOOT2_TAG_TYPE_FRAMEBUFFER) {
            struct multiboot_tag_framebuffer* fb = (void*)tag;
            serial_write("Framebuffer tag found\n");

            g_fb_addr = fb->framebuffer_addr;
            g_fb_pitch = fb->framebuffer_pitch;
            g_fb_width = fb->framebuffer_width;
            g_fb_height = fb->framebuffer_height;

            serial_write("Framebuffer info:\n");
            serial_write("Address: 0x");
            char hex_str[20];
            uint64_to_hex(g_fb_addr, hex_str);
            serial_write(hex_str);
            serial_write("\nPitch: ");
            serial_write(g_fb_pitch);
            serial_write(" Width: ");
            serial_write(g_fb_width);
            serial_write(" Height: ");
            serial_write(g_fb_height);
            serial_write("\n");

            // Allocate backbuffer using malloc
            size_t backbuffer_size = g_fb_pitch * g_fb_height;

            // Map framebuffer pages (4KB aligned)
            uint64_t fb_start = g_fb_addr & ~0xFFF;
            uint64_t fb_end = (g_fb_addr + backbuffer_size + 0xFFF) & ~0xFFF;
            for (uint64_t addr = fb_start; addr < fb_end; addr += 0x1000) {
                if (map_page(addr, addr, PAGE_PRESENT | PAGE_WRITE) != 0) {
                    serial_write("Failed to map framebuffer page\n");
                    return;
                }
            }
            serial_write("Framebuffer pages mapped\n");

            if (fb->framebuffer_type == 1) { // RGB
                uint8_t* color_info = (uint8_t*)fb + 24;
                uint32_t red_pos = color_info[0];
                uint32_t red_size = color_info[1];
                uint32_t green_pos = color_info[2];
                uint32_t green_size = color_info[3];
                uint32_t blue_pos = color_info[4];
                uint32_t blue_size = color_info[5];
                serial_write("Color info set\n");
            } else {
                serial_write("Unsupported framebuffer type\n");
            }
        }
        tag = (struct multiboot_tag*)(((uintptr_t)tag + tag->size + 7) & ~(uintptr_t)7);
    }
}

uint32_t make_color(uint8_t r, uint8_t g, uint8_t b) {
    return ((r << 16) | (g << 8) | (b << 0));
}

void putpixel(uint64_t fb_addr, uint32_t pitch, uint32_t x, uint32_t y, uint32_t color) {
    uint32_t* pixel = (uint32_t*)(fb_addr + y * pitch + x * 4);
    *pixel = color;
}

// Draw rectangle (filled)
void draw_rect(int x, int y, int width, int height, uint32_t color) {
    for (int py = y; py < y + height; py++) {
        for (int px = x; px < x + width; px++) {
            put_pixel(px, py, color);
        }
    }
}

void fill_screen(uint64_t fb_addr, uint32_t width, uint32_t height, uint32_t pitch, uint32_t color) {
    for (uint32_t y = 0; y < height; ++y) {
        uint32_t* row = (uint32_t*)(uintptr_t)(fb_addr + y * pitch);
        for (uint32_t x = 0; x < width; ++x) {
            row[x] = color;
        }
    }
}

// Initialize MFS backbuffer
int renderer_init_mfs_backbuffer(uint32_t width, uint32_t height, uint32_t pitch) {
    backbuffer_width = width;
    backbuffer_height = height;
    backbuffer_pitch = pitch;

    size_t backbuffer_size = pitch * height;

    // Allocate backbuffer segment in MFS root directory
    backbuffer_segment = mfs_seg("backbuffer", backbuffer_size, mfs_sb.root_dir);
    if (!backbuffer_segment) {
        serial_write("renderer_init_mfs_backbuffer: Failed to allocate backbuffer segment\n");
        return -1;
    }

    // Clear backbuffer segment to zero using mfs_write
    uint8_t zero = 0;
    for (size_t offset = 0; offset < backbuffer_size; offset++) {
        mfs_write(backbuffer_segment, offset, &zero, 1);
    }

	asm volatile ("int $0x21"); // Only in real mode

    serial_write("renderer_init_mfs_backbuffer: Backbuffer segment allocated and cleared\n");
    return 0;
}

// Put pixel function
void put_pixel(int x, int y, uint32_t color) {
    if (x < 0 || x >= backbuffer_width || y < 0 || y >= backbuffer_height) {
        return;
    }
    
    size_t offset = (y * backbuffer_width + x) * 4;
    mfs_write(backbuffer_segment, offset, &color, 4);
}

// Draw a pixel to the MFS backbuffer
void renderer_putpixel_mfs(int x, int y, uint32_t color) {
    if (!backbuffer_segment) return;
    if (x < 0 || y < 0 || x >= (int)backbuffer_width || y >= (int)backbuffer_height) return;

    uint32_t offset = y * backbuffer_pitch + x * 4;
    mfs_write(backbuffer_segment, offset, &color, 4);
}

// Fill a rectangle in the MFS backbuffer
void renderer_fill_rect_mfs(int x, int y, int w, int h, uint32_t color) {
    if (!backbuffer_segment) return;

    for (int dy = 0; dy < h; ++dy) {
        int py = y + dy;
        if (py < 0 || py >= (int)backbuffer_height) continue;

        for (int dx = 0; dx < w; ++dx) {
            int px = x + dx;
            if (px < 0 || px >= (int)backbuffer_width) continue;

            uint32_t offset = py * backbuffer_pitch + px * 4;
            mfs_write(backbuffer_segment, offset, &color, 4);
        }
    }
}

// Present the MFS backbuffer to the framebuffer without memcpy
void renderer_present_mfs (void) {
    if (!backbuffer_segment) return;

    size_t backbuffer_size = backbuffer_pitch * backbuffer_height;
    size_t chunk_size = 4096; // Read and write in chunks
    uint8_t temp_buffer[4096];

    for (size_t offset = 0; offset < backbuffer_size; offset += chunk_size) {
        size_t to_read = (backbuffer_size - offset) > chunk_size ? chunk_size : (backbuffer_size - offset);
        mfs_read(backbuffer_segment, offset, temp_buffer, to_read);
        // Write chunk directly to framebuffer memory
        uint8_t* fb_ptr = (uint8_t*)(g_fb_addr + offset);
        for (size_t i = 0; i < to_read; i++) {
            fb_ptr[i] = temp_buffer[i];
        }
    }
}

// Example blinking animation using MFS backbuffer
void renderer_blink_animation_mfs(int x, int y, int w, int h, uint32_t color1, uint32_t color2, int frames, int delay_loops) {
    for (int i = 0; i < frames; i++) {
        if (i % 2 == 0) {
            renderer_fill_rect_mfs(x, y, w, h, color1);
        } else {
            renderer_fill_rect_mfs(x, y, w, h, color2);
        }
        renderer_present_mfs();

        // Simple delay loop for blinking speed control
        for (volatile int d = 0; d < delay_loops; d++);
    }
}

// Example usage after framebuffer initialization and MFS init
void test_renderer_mfs (void) {
    if (renderer_init_mfs_backbuffer(g_fb_width, g_fb_height, g_fb_pitch) != 0) {
        serial_write("test_renderer_mfs: Failed to initialize MFS backbuffer\n");
        return;
    }

    // Clear backbuffer to black initially
    renderer_fill_rect_mfs(0, 0, g_fb_width, g_fb_height, make_color(0, 0, 0));

    int rect_w = 50;
    int rect_h = 50;
    int x = 0;
    int y = g_fb_height / 2 - rect_h / 2;
    int dx = 2;
    int scale_direction = 1;

    for (int frame = 0; frame < 9999; frame++) {
        // Clear backbuffer each frame
        renderer_fill_rect_mfs(0, 0, g_fb_width, g_fb_height, make_color(0, 0, 0));

        // Draw moving and scaling rectangle
        renderer_fill_rect_mfs(x, y, rect_w, rect_h, make_color(255, 128, 0));

        // Present backbuffer to framebuffer
        renderer_present_mfs();

        // Update position
        x += dx;
        if (x < 0 || x + rect_w > (int)g_fb_width) {
            dx = -dx;
            x += dx;
        }

        // Update scale
        rect_w += scale_direction;
        rect_h += scale_direction;
        if (rect_w > 100 || rect_w < 30) {
            scale_direction = -scale_direction;
        }

        // Simple delay loop for frame timing
        for (volatile int d = 0; d < 50000; d++);
    }
}

// Clears the entire screen with a given color using mfs_write
void clear_screen_vbe(uint32_t color) {
    for (uint32_t y = 0; y < g_fb_height; y++) {
        for (uint32_t x = 0; x < g_fb_width; x++) {
            uint64_t offset = y * g_fb_pitch + x * 4;
            mfs_write(backbuffer_segment, offset, &color, sizeof(uint32_t));
        }
    }
}

// Render a single character bitmap at pixel coordinates (px, py) on the VBE screen
// using the loaded font bitmap. Each character is 8x16 pixels.
// Renders a single character into the MFS-backed framebuffer
void render_char_vbe(int px, int py, char c, uint32_t color) {
    if (!backbuffer_segment) return;

    if (px < 0 || py < 0 ||
        px + FONT_CHAR_WIDTH > (int)g_fb_width ||
        py + FONT_CHAR_HEIGHT > (int)g_fb_height) return;

    uint8_t* bitmap = font_bitmaps[(uint8_t)c];

    for (int row = 0; row < FONT_CHAR_HEIGHT; row++) {
        uint8_t bits = bitmap[row];

        for (int bit = 0; bit < FONT_CHAR_WIDTH; bit++) {
            if (bits & (1 << (7 - bit))) {
                int x = px + bit;
                int y = py + row;

                uint64_t offset = y * g_fb_pitch + x * 4;
                mfs_write(backbuffer_segment, offset, &color, sizeof(uint32_t));  // Replace NULL with the proper mfs_entry_t* if available
            }
        }
    }
}

void print_vbe(const char* str, uint32_t color) {
    if (!str) return;

    int x = 0, y = 0;
    size_t len = strlen(str);  // Total string length (optional use)

    for (size_t i = 0; i < len; i++) {
        if (str[i] == '\n') {
            x = 0;
            y++;
            continue;
        }
        render_char_vbe(x * FONT_CHAR_WIDTH, y * FONT_CHAR_HEIGHT, str[i], color);
        x++;
        if (x >= g_fb_height / FONT_CHAR_HEIGHT) {
            x = 0;
            y++;
        }
    }
}

void print_at_vbe(int x, int y, const char* str, uint32_t color) {
    if (!str) return;

    int cx = x, cy = y;
    size_t len = strlen(str);

    for (size_t i = 0; i < len; i++) {
        if (str[i] == '\n') {
            cx = x;
            cy++;
            continue;
        }
        render_char_vbe(cx * FONT_CHAR_WIDTH, cy * FONT_CHAR_HEIGHT, str[i], color);
        cx++;
        if (cx >= g_fb_height / FONT_CHAR_HEIGHT) {
            cx = x;
            cy++;
        }
    }
}

void key_input (void) {
    int ch = kernel_getchar();
    if (ch == -1) return; // No input

    static int cursor_x = 0;
    static int cursor_y = 0;

    uint32_t color = make_color(255, 255, 255);  // White

    // Glyph position in pixels
    int px = cursor_x * FONT_CHAR_WIDTH;
    int py = cursor_y * FONT_CHAR_HEIGHT;

    render_char_vbe(px, py, (char)ch, color);

    // Advance cursor horizontally
    cursor_x++;
    if (cursor_x >= (int)(g_fb_width / FONT_CHAR_WIDTH)) {
        cursor_x = 0;
        cursor_y++;

        // Basic scroll logic (placeholder — upgrade to buffer scroll later)
        if (cursor_y >= (int)(g_fb_height / FONT_CHAR_HEIGHT))
            cursor_y = 0;
    }

    renderer_present_mfs();
}
