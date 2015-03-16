DOCS :=	\
	kdbus.xml		\
	kdbus.bus.xml		\
	kdbus.connection.xml	\
	kdbus.endpoint.xml	\
	kdbus.fs.xml		\
	kdbus.item.xml		\
	kdbus.match.xml		\
	kdbus.message.xml	\
	kdbus.name.xml		\
	kdbus.policy.xml	\
	kdbus.pool.xml

XMLFILES := $(addprefix $(obj)/,$(DOCS))
MANFILES := $(patsubst %.xml, %.7, $(XMLFILES))
HTMLFILES := $(patsubst %.xml, %.html, $(XMLFILES))

XMLTO_ARGS := -m $(srctree)/$(src)/stylesheet.xsl --skip-validation

quiet_cmd_db2man = MAN     $@
      cmd_db2man = xmlto man $(XMLTO_ARGS) -o $(obj) $<
%.7: %.xml
	@(which xmlto > /dev/null 2>&1) || \
	 (echo "*** You need to install xmlto ***"; \
	  exit 1)
	$(call cmd,db2man)

quiet_cmd_db2html = HTML    $@
      cmd_db2html = xmlto html-nochunks $(XMLTO_ARGS) -o $(obj) $<
%.html: %.xml
	@(which xmlto > /dev/null 2>&1) || \
	 (echo "*** You need to install xmlto ***"; \
	  exit 1)
	$(call cmd,db2html)

mandocs: $(MANFILES)

htmldocs: $(HTMLFILES)

clean-files := $(MANFILES) $(HTMLFILES)
