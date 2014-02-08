README.txt for ATC-NY Mac Memory Reader[tm]
-------------------------------------------

Copyright (c) 2010-2011 Architecture Technology Corporation.
All rights reserved.


Mac Memory Reader generates a Mach-O dump file of the contents of a running
system's physical memory (RAM).  It is intended to be run directly on the
target machine, with output to a USB drive or similar.  You must be familiar
with running command line tools to use this program.  You should also be
aware of the forensic implications of running a process (in RAM) to gather
the contents of that same RAM.

See LICENSE.txt for license information.

If you are interested in a full-featured forensic suite that includes
RAM capture capabilities, see Mac Marshal: http://www.macmarshal.com/

Web site:
http://www.cybermarshal.com/index.php/cyber-marshal-utilities/mac-memory-reader

Please e-mail support@macmarshal.com or use the 'support' section of the web
site above if you've found a problem with the software.


Usage
-----

1. Ensure you have an external drive with sufficient space for the RAM
   image.  Note that most USB drives are formatted as FAT-32, which
   limits files to 4GB in size; see below if you are saving to a FAT-32
   drive.
   
2. Change into the MacMemoryReader directory (the directory containing
   this README.txt file).
   
3. Execute Mac Memory Reader as root:
      sudo ./MacMemoryReader <filename>
   where <filename> is the path to write memory to, such as
   /Volumes/STORAGE/ram_dump.mach-o

The output file will be slightly larger than physical memory due to the
Mach-O header and block alignment constraints.  If the filename is '-',
memory is dumped to stdout.

If you are saving the RAM snapshot to a FAT-32 formatted USB drive, FAT-32's
file size restrictions will prevent you from writing RAM snapshots that are
4GB or larger.  To get around this limitation, split the output into
multiple 2GB files using a command line such as the following:
  sudo ./MacMemoryReader - | split -b 2048m - ram_dump.mach-o.
This will create ram_dump.mach-o.aa, ram_dump.mach-o.ab, etc.

MacMemoryReader can compute hashes on the fly if needed: add '-H hashtype'
(where hashtype is one of MD5, SHA-1, SHA-256, or SHA-512) arguments to
have hashes printed on stderr.  For example,
'./MacMemoryReader -H MD5 -H SHA-1 ...' will compute both MD5 and SHA-1
hashes of the memory dump.

Adding the -d flag to MacMemoryReader will give verbose debugging
information as the RAM snapshot is being written.  Note that the
-v flag of previous versions is no longer available -- progress 
information is now provided by default.

'./MacMemoryReader -h' gives the full usage message.



Interpreting the Results
------------------------

Mac Memory Reader saves RAM snapshots as 32-bit or 64-bit Mach-O format
files (depending on the size of physical memory)[1].  Physical memory is
often segmented rather than contiguous, especially on Intel-based Macs.
The Mach-O file format allows multiple segments of memory to be
represented, preserving offset information.  The format contains a header
listing the segments of memory contained in the file, followed by the memory
segments themselves.  The command line "otool" program can be used to examine
Mach-O file headers.  For instance, "otool -l memoryfile" (replacing
memoryfile with the path to the RAM snapshot file) will list all the
physical memory segments saved in the snapshot.

MacMemoryReader ignores memory-mapped IO device segments and memory ports;
it reads only physical RAM.

If virtual machine software that uses hypervisor technology, such as
Parallels, is installed on the target, the physical memory snapshot will be
slightly smaller than the full size of RAM on the machine.  This happens
because the hypervisor is controlling access to the underlying physical
hardware and reserving some memory for itself.  The RAM snapshot will
include RAM used by guest virtual machines.

There are currently very few tools to analyze physical memory dumps from
Mac OS X machines.  Hex editors, string extraction tools, search tools,
and file carvers are all useful for extracting data.  Aside from the file
header, Mach-O files are simply raw data files, simplifying search and data
extraction.  (If you use the command-line program /usr/bin/strings to
examine the file, be aware that it treats Mach-O files specially and only
examines part of the file by default.  Use the '-' option to force strings
to examine the whole file. For example, 'strings - ram_dump.mach-o')

The Mac OS X versions of the 'strings' and 'otool' commands try to map the
entire file they're reading into memory.  You may get "cannot allocate memory"
errors if either
  1 - the machine you're analyzing RAM on has less physical memory than
      the machine from which the snapshot was taken, or
  2 - the snapshot you're analyzing RAM on is running the 32-bit kernel
      (or OS X 10.5 or earlier) and the snapshot was taking on a machine
      running the 64-bit kernel (or 10.7 and later).
To run 'strings' anyway, you can force it to not map the entire file at
once: "cat ram_dump.mach-o | strings - -"  There is no workaround for 'otool.'

Important note: Pieces of the MacMemoryReader executable code and data will
certainly appear within the RAM snapshot, simply because MacMemoryReader is
running in the same memory space being acquired.  This is a known "footprint"
and aspect of live analysis.

[1] http://developer.apple.com/documentation/DeveloperTools/Conceptual/MachORuntime/index.html


Implementation Notes
--------------------

MacMemoryReader uses a kernel extension to create temporary, read-only /dev/mem
and /dev/pmap devices.  /dev/pmap shows the physical memory map.  /dev/mem
provides the same functionality provided by /dev/mem on other Unix operating
systems.  That is, it virtualizes the physical memory space.  Processes can
read at specific offsets to retrieve the data at those physical addresses.
/dev/mem only provides access to physical memory of the following types, as
defined by EFI: "available", Loader Code, Loader Data, Bootstrap Code,
Bootstrap Data, Runtime Code, Runtime Data, and, optionally, "reserved".
It does not allow access to memory ports or memory-mapped I/O devices,
so it cannot be used to write device drivers.

MacMemoryReader reads from the /dev/mem device and constructs a Mach-O file
containing the offsets and lengths of each readable segment of physical
RAM.  Mach-O file segments are named according to the EFI type of the
corresponding physical memory segment (e.g., "LoaderCode").


Changes
-------

Version 3.0.0

- new -r flag to dump "reserved" sections such as shared video memory;
  this is still experimental
  
  
Version 2.0.4

- support for Mac OS X 10.7 (Lion)


Version 2.0.3

- improve usefulness of stderr metadata provided during runs
- -v option removed and replaced by -d
- dumps now include LoaderCode, LoaderData, BS_code, BS_data, RT_code,
  and RT_data sections (which are all generally small, but include
  tables necessary to bootstrap Mac memory analysis)


Version 2.0.2

- fixed two bugs that would prevent memory dumps from working on 10.4
  and 10.5
