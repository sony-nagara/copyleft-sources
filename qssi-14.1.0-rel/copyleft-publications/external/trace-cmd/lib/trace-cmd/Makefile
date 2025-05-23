# SPDX-License-Identifier: GPL-2.0

include $(src)/scripts/utils.mk

bdir:=$(obj)/lib/trace-cmd
ldir:=$(src)/lib/trace-cmd

DEFAULT_TARGET = $(LIBTRACECMD_STATIC)

OBJS =
OBJS += trace-hash.o
OBJS += trace-hooks.o
OBJS += trace-input.o
OBJS += trace-output.o
OBJS += trace-recorder.o
OBJS += trace-util.o
OBJS += trace-filter-hash.o
OBJS += trace-msg.o
OBJS += trace-plugin.o
ifeq ($(PERF_DEFINED), 1)
OBJS += trace-perf.o
endif
OBJS += trace-timesync.o
OBJS += trace-timesync-ptp.o
ifeq ($(VSOCK_DEFINED), 1)
OBJS += trace-timesync-kvm.o
endif
OBJS += trace-compress.o
ifeq ($(ZLIB_INSTALLED), 1)
OBJS += trace-compress-zlib.o
endif
ifeq ($(ZSTD_INSTALLED), 1)
OBJS += trace-compress-zstd.o
endif

# Additional util objects
OBJS += trace-blk-hack.o
OBJS += trace-ftrace.o

OBJS := $(OBJS:%.o=$(bdir)/%.o)
DEPS := $(OBJS:$(bdir)/%.o=$(bdir)/.%.d)

all: $(DEFAULT_TARGET)

$(bdir):
	@mkdir -p $(bdir)

$(OBJS): | $(bdir)
$(DEPS): | $(bdir)

$(LIBTRACECMD_STATIC): $(OBJS)
	$(Q)$(call do_build_static_lib)

LIBS = $(LIBTRACEEVENT_LDLAGS) $(LIBTRACEFS_LDLAGS) $(LIBZSTD_LDLAGS) -lpthread

ifeq ($(ZLIB_INSTALLED), 1)
LIBS += -lz
endif

$(LIBTRACECMD_SHARED_VERSION): $(LIBTRACECMD_SHARED)
	@ln -sf $(<F) $@

$(LIBTRACECMD_SHARED_SO): $(LIBTRACECMD_SHARED_VERSION)
	@ln -sf $(<F) $@

libtracecmd.so: force $(LIBTRACECMD_SHARED_SO)

$(LIBTRACECMD_SHARED): $(OBJS)
	$(Q)$(call do_compile_shared_library,$(notdir $(LIBTRACECMD_SHARED_VERSION)))

$(bdir)/%.o: %.c
	$(Q)$(call do_fpic_compile)

$(DEPS): $(bdir)/.%.d: %.c
	$(Q)$(CC) -M -MT $(bdir)/$*.o $(CPPFLAGS) $(CFLAGS) $< > $@

$(OBJS): $(bdir)/%.o : $(bdir)/.%.d

ifeq ("$(DESTDIR)", "")
# If DESTDIR is not defined, then test if after installing the library
# and running ldconfig, if the library is visible by ld.so.
# If not, add the path to /etc/ld.so.conf.d/trace.conf and run ldconfig again.
define install_ld_config
	if $(LDCONFIG); then \
		if ! grep -q "^$(libdir)$$" $(LD_SO_CONF_PATH)/* ; then \
			echo here;\
			$(CC) -o $(bdir)/test $(ldir)/test.c -I $(includedir_SQ) \
				-L $(libdir_SQ) -ltracecmd &> /dev/null; \
			if ! $(bdir)/test &> /dev/null; then \
				$(call print_install,trace.conf,$(LD_SO_CONF_PATH)) \
				echo $(libdir_SQ) >> $(LD_SO_CONF_PATH)/trace.conf; \
				$(LDCONFIG); \
			fi; \
			$(RM) $(bdir)/test; \
		fi; \
	fi
endef
else
# If installing to a location for another machine or package, do not bother
# with running ldconfig.
define install_ld_config
endef
endif # DESTDIR = ""

install_pkgconfig: $(PKG_CONFIG_FILE)
	$(Q)$(call do_install_pkgconfig_file,$(prefix))

install_libs: install_pkgconfig
	$(Q)$(call do_install,$(LIBTRACECMD_SHARED),$(libdir_SQ))
	$(Q)$(call print_install,$(LIBTRACECMD_SHARED_VERSION),$(DESTDIR)$(libdir_SQ))
	$(Q)cp -fpR $(LIBTRACECMD_SHARED_VERSION) $(DESTDIR)$(libdir_SQ)
	$(Q)$(call print_install,$(LIBTRACECMD_SHARED_SO),$(DESTDIR)$(libdir_SQ))
	$(Q)cp -fpR $(LIBTRACECMD_SHARED_SO) $(DESTDIR)$(libdir_SQ)
	$(Q)$(call do_install,$(src)/include/trace-cmd/trace-cmd.h,$(includedir_SQ)/trace-cmd,644)
	$(Q)$(call install_ld_config)

dep_includes := $(wildcard $(DEPS))

ifneq ($(dep_includes),)
  include $(dep_includes)
endif

clean:
	$(RM) $(bdir)/*.a $(bdir)/*.so $(bdir)/*.so.* $(bdir)/*.o $(bdir)/.*.d

.PHONY: clean

PHONY += force
force:
