CLANG	?= clang -isysroot /Applications/Xcode.app/Contents/Developer/Platforms/iPhoneOS.platform/Developer/SDKs/iPhoneOS9.2.sdk
ARCH	?= -arch arm64 -arch armv7

INCDIR = iphone-include
MIGDIR = mig

LIBKERN ?= /Applications/Xcode.app/Contents/Developer/Platforms/MacOSX.platform/Developer/SDKs/MacOSX.sdk/usr/include
OSFMK ?= /Applications/Xcode.app/Contents/Developer/Platforms/MacOSX.platform/Developer/SDKs/MacOSX.sdk/usr/include
IOKIT ?= /Applications/Xcode.app/Contents/Developer/Platforms/MacOSX.platform/Developer/SDKs/MacOSX.sdk/System/Library/Frameworks/IOKit.framework/Headers

MIG_CC	?= mig -isysroot /Applications/Xcode.app/Contents/Developer/Platforms/iPhoneOS.platform/Developer/SDKs/iPhoneOS10.2.sdk
MIG_FLAGS	?= -arch arm64 -DIOKIT -I../$(INCDIR)


C_FLAGS	?= -I./include
LD_LIBS	?= -framework IOKit -framework CoreFoundation

.PHONY: all clean

all: mig
	$(CLANG) $(ARCH) $(C_FLAGS) $(LD_LIBS) -DDEVBUILD *.c -o test -miphoneos-version-min=8.0
	strip test
	ldid -Sent.xml test
	$(CLANG) $(ARCH) $(C_FLAGS) $(LD_LIBS) *.c -miphoneos-version-min=8.0 -c -DAPP -DNOROOT
	-$(RM) *.a
	ar rcs sockpuppet.a *.o
	-$(RM) *.o
	
$(INCDIR):
	mkdir $(INCDIR)
	ln -s $(IOKIT) $(INCDIR)/IOKit
	mkdir $(INCDIR)/libkern
	ln -s $(LIBKERN)/libkern/OSTypes.h $(INCDIR)/libkern/OSTypes.h
	mkdir $(INCDIR)/mach
	ln -s $(OSFMK)/mach/clock_types.defs $(INCDIR)/mach/clock_types.defs
	ln -s $(OSFMK)/mach/mach_types.defs $(INCDIR)/mach/mach_types.defs
	ln -s $(OSFMK)/mach/std_types.defs $(INCDIR)/mach/std_types.defs
	mkdir $(INCDIR)/mach/machine
	ln -s $(OSFMK)/mach/machine/machine_types.defs $(INCDIR)/mach/machine/machine_types.defs

$(MIGDIR): | $(INCDIR)
	mkdir $(MIGDIR)
	cd $(MIGDIR) && $(MIG_CC) $(MIG_FLAGS) $(OSFMK)/device/device.defs

clean:
	-$(RM) test
	-$(RM) -r mig
	-$(RM) -r iphone-include
	-$(RM) *.o
	-$(RM) *.a
