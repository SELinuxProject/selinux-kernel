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

XMLTO_ARGS := -m $(obj)/stylesheet.xsl

%.7: %.xml
	xmlto man $(XMLTO_ARGS) -o . $<

%.html: %.xml
	xmlto html-nochunks $(XMLTO_ARGS) -o . $<

mandocs: $(MANFILES)

htmldocs: $(HTMLFILES)

clean-files := $(MANFILES) $(HTMLFILES)
