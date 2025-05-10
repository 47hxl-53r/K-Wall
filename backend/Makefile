# Module name
obj-m := kwall.o

# Source files
kwall-objs := kwall_src.o

# Kernel build directory
KDIR := /lib/modules/$(shell uname -r)/build
PWD := $(shell pwd)

# Install path (modprobe scans this)
INSTALL_PATH := /lib/modules/$(shell uname -r)/extra

# Default target: build the module
all:
	$(MAKE) -C $(KDIR) M=$(PWD) modules

# Install to system but do NOT auto-load
install:
	@echo "Building and installing kwall.ko..."
	$(MAKE) -C $(KDIR) M=$(PWD) modules
	@sudo mkdir -p $(INSTALL_PATH)
	@sudo install -m 644 kwall.ko $(INSTALL_PATH)/
	@sudo depmod -a
	@echo "kwall.ko installed to $(INSTALL_PATH)."
	@echo "You can now load it manually or via startup script: sudo modprobe kwall"

# Uninstall module
uninstall:
	@echo "Removing kwall.ko..."
	@sudo rm -f $(INSTALL_PATH)/kwall.ko
	@sudo depmod -a
	@echo "kwall.ko removed from $(INSTALL_PATH)."

# Clean up build artifacts
clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean
