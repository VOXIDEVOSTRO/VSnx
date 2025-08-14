# VSnx
This is NON-POSIX x86_64 independent OS. This OS is from complete scratch. This OS is unique in architecture because of these unique components:
1. MFS(Memory Filesystem): This is entry based virtual memory. Instead of use of raw addresses it used entry based system like named entities like directory(folder) and segment(file). 

2. Multithreading via emulated stacks: This unique of Multithreading is orchestrated by the MFS. This stackless method was used so to account for the entry based memory management.

3. Multitasking: The OS is single core. meaning it has no SMP support (cannot use Multiple cores of the CPU). and the context switch is handled to save process state (thread state) by creating a snapshot segments which takes a complete snapshot of the thread and saves it up to a segment to restore later via round robin.

4. Overall architecture: The OS has lots of uniqueness filled up and also some external source code from: For FAT32 driver:
https://github.com/hairymnstr/gristle from hairymnstr.

More insight:
This OS was mostly coded with AI tools LLM like Claude sonnet 3.7 and 4. The whole sole of this project was to code with AI to form a real operating system capable to run on real system. With the design of a Human and all code precision work from AI. This was to check how AI is good for more advanced stuff like operating systems and how they can make on their own with human interaction and how well they design the concepts.