# kbuild trick to avoid linker error. Can be omitted if a module is built.
obj- := dummy.o

hostprogs-$(CONFIG_SAMPLE_KDBUS) += kdbus-workers

always := $(hostprogs-y)

HOSTCFLAGS_kdbus-workers.o += -I$(objtree)/usr/include
HOSTLOADLIBES_kdbus-workers := -lrt
