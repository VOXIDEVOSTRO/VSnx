#include "include.h"

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

/*==============================================================================================================
  FONTS
================================================================================================================*/

int load_font(const char* filename) {
    int fd = fs_open(filename);
    if (fd < 0) {
        serial_write("load_font: Failed to open font file:");
        serial_write(filename);
        serial_write("\n");
        return -1;
    }

    size_t font_file_size = FONT_NUM_CHARS * FONT_CHAR_HEIGHT;
    uint8_t* font_buffer = (uint8_t*)malloc(font_file_size);
    if (!font_buffer) {
        serial_write("load_font: Failed to allocate memory\n");
        fs_close(fd);
        return -1;
    }

    int bytes_read = fs_read(fd, font_buffer, font_file_size);
    fs_close(fd);

    if (bytes_read != (int)font_file_size) {
        serial_write("load_font: Incomplete font read\n");
        free(font_buffer);
        return -1;
    }

    for (int ch = 0; ch < FONT_NUM_CHARS; ch++) {
        for (int row = 0; row < FONT_CHAR_HEIGHT; row++) {
            font_bitmaps[ch][row] = font_buffer[ch * FONT_CHAR_HEIGHT + row];
        }
    }

    free(font_buffer);
    serial_write("load_font: Font loaded successfully\n");
    return 0;

}
