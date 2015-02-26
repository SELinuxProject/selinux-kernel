# kbuild trick to avoid linker error. Can be omitted if a module is built.
obj- := dummy.o

hostprogs-y += kdbus-workers

always := $(hostprogs-y)

HOSTCFLAGS_kdbus-workers.o +=		\
	-I$(objtree)/usr/include/	\
	-I$(objtree)/include/uapi/
