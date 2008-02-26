opdir		 = $(datadir)/vyatta-op/templates

xsldir          = @XSLDIR@

bin_sudo_usersdir = $(bindir)/sudo-users

xsl_DATA =

bin_sudo_users_SCRIPTS = scripts/firewall/vyatta-show-firewall.pl

xsl_DATA        += src/xsl/show_firewall_detail.xsl
xsl_DATA        += src/xsl/show_firewall_statistics_brief.xsl
xsl_DATA        += src/xsl/show_firewall_statistics.xsl
xsl_DATA        += src/xsl/show_firewall.xsl

cpiop = find  . ! -regex '\(.*~\|.*\.bak\|.*\.swp\|.*\#.*\#\)' -print0 | \
	cpio -0pd

install-exec-hook:
	mkdir -p $(DESTDIR)$(opdir)
	cd templates; $(cpiop) $(DESTDIR)$(opdir)


