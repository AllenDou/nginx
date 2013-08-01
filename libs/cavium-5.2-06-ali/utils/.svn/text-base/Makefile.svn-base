BASEDIR= ..
include $(BASEDIR)/platform

all: all-utils

all-utils: os_depend_make

os_depend_make:
	@if test $(OS) = Linux ; then \
		$(MAKE) -f utils-$(OS).mk all-utils-$(OS); \
	fi;
	@if test $(OS) = FreeBSD ; then \
		$(MAKE) -f utils-$(OS).mk all-utils-$(OS); \
	fi;
	
clean: clean-utils

clean-utils: os_depend_clean

os_depend_clean:
	@if test $(OS) = Linux ; then \
		$(MAKE) -f utils-$(OS).mk clean-utils-$(OS); \
	fi;
	@if test $(OS) = FreeBSD ; then \
		$(MAKE) -f utils-$(OS).mk clean-utils-$(OS); \
	fi;
