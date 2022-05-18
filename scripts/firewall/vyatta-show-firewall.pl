#!/usr/bin/perl

use lib "/opt/vyatta/share/perl5/";
use Vyatta::Config;
use Vyatta::Interface;
use Vyatta::IpTables::Rule;
use Vyatta::IpTables::AddressFilter;
use Vyatta::Zone;

use warnings;
use strict;

exit 1 if ($#ARGV < 1);
my $tree_chain = $ARGV[0];
my $xsl_file = $ARGV[1];
my $rule_num = $ARGV[2];    # rule number to match (optional)

my $max_rule = 1000000;

if (! -e $xsl_file) {
  print "Invalid XSL file \"$xsl_file\"\n";
  exit 1;
}

if (defined($rule_num) && (!($rule_num =~ /^\d+$/) || ($rule_num > $max_rule))) {
  print "Invalid rule number \"$rule_num\"\n";
  exit 1;
}

sub convert_to_easyunits {
  my $size = shift;
  my @args = qw/B K M G T P E Z Y/;

  while (@args && $size > 1000) {
    shift @args;
    $size /= 1000;
  }

  if ($args[0] eq 'B') {
    $size = sprintf("%d",$size);
    return "$size";
  } else {
    $size = sprintf("%.2f",$size);
    return "$size$args[0]";
  }
}

sub numerically { $a <=> $b; }
my $format1  = "%-9s %-8s %-9s %-8s %-40s";
my $format2  = "  %-78s";

# mapping from config node to root config node. 
my %root_hash = ( 'name'        => 'firewall',
                  'ipv6-name'   => 'firewall',
                  'route'       => 'policy',
                  'ipv6-route'  => 'policy');
                  
sub show_interfaces_zones {
  my ($chain, $tree) = @_;

  my $cfg = new Vyatta::Config;
  my @int_strs = ();
  for (Vyatta::Interface::get_effective_interfaces()) {
    my ($iname, $ipath) = ($_->{name}, $_->{path});
    for my $dir ($cfg->listOrigNodes("$ipath $root_hash{$tree}")) {
      my $path;
      if ($tree eq 'route' || $tree eq 'ipv6-route') {
        $path = "$ipath $root_hash{$tree} $dir";
      } else {
        $path = "$ipath $root_hash{$tree} $dir $tree";
      }
      my $ichain = $cfg->returnOrigValue("$path");
      if (defined($ichain) and $ichain eq $chain) {
        $dir =~ y/a-z/A-Z/;
        push @int_strs, "($iname,$dir)";
      }
    }
  }
  if (scalar(@int_strs) > 0) {
    print "\n\n Active on " . (join ' ', @int_strs);
  }
  print "\n";

  # check if chain used to filter traffic between zones
  my $used_in_zonefw=0;
  my @all_zones = Vyatta::Zone::get_all_zones("listOrigNodes");
  foreach my $zone (sort(@all_zones)) {
     my @from_zones = Vyatta::Zone::get_from_zones("listOrigNodes", $zone);
     my @from_zones_using_this_chain=();
     foreach my $from_zone (sort(@from_zones)) {
        my $fw_ruleset=Vyatta::Zone::get_firewall_ruleset("returnOrigValue",
                        $zone, $from_zone, $tree);
        if (defined $fw_ruleset && $fw_ruleset eq $chain) {
          push (@from_zones_using_this_chain, $from_zone);
          if ($used_in_zonefw == 0) {
            print "\n Active on traffic to -\n";
            $used_in_zonefw++;
          }
        }
     }
     if (scalar(@from_zones_using_this_chain) > 0) {
       my $single_or_multiple_zone = 'zone';
       if (scalar(@from_zones_using_this_chain) > 1) {
          $single_or_multiple_zone = 'zones';
       }
       my $string_fromzones=join(', ', sort(@from_zones_using_this_chain));
       print "  zone [$zone] from $single_or_multiple_zone [$string_fromzones]\n";
     }
  }

  if ((scalar(@int_strs) == 0) && ($used_in_zonefw == 0)) {
    print "\n Inactive - Not applied to any interfaces or zones.\n";
  } 
  print "\n";
}

# mapping from iptables/ip6tables target to config action
my %target_hash = ('RETURN'   => 'accept',
                   'DROP'     => 'drop',
                   'NFQUEUE'  => 'inspect',
                   'REJECT'   => 'reject',
                   'DSCP'     => 'modify',
                   'MARK'     => 'modify');

# mapping from config node to iptables/ip6tables table
my %table_hash = ( 'name'        => 'filter',
                   'ipv6-name'   => 'filter',
                   'route'       => 'mangle',
                   'ipv6-route'  => 'mangle' );

# mapping from config node to iptables command. 
my %cmd_hash = ( 'name'        => 'iptables',
                 'ipv6-name'   => 'ip6tables',
                 'route'       => 'iptables',
                 'ipv6-route'  => 'ip6tables');
                 
# mapping from config node to printable string describing it.
my %description_hash = ( 'name'        => 'IPv4 Firewall',
                         'ipv6-name'   => 'IPv6 Firewall',
                         'route'       => 'IPv4 Policy Route',
                         'ipv6-route'  => 'IPv6 Policy Route');


# mapping from config node to IP version string.
my %ip_version_hash = ( 'name'        => 'ipv4',
                        'ipv6-name'   => 'ipv6',
                        'route'       => 'ipv4',
                        'ipv6-route'  => 'ipv6');

sub show_chain($$$) {
  my ($chain, $fh, $tree) = @_;

  my $table = $table_hash{$tree};
  my $iptables_cmd = $cmd_hash{$tree};

  open my $iptables, "-|"
      or exec "sudo", "/sbin/$iptables_cmd", "-t", $table, "-L", $chain, "-vnx"
      or exit 1;
  my @stats = ();
  while (<$iptables>) {
    if (!/^\s*(\d+[KMG]?)\s+(\d+[KMG]?)\s/) {
      next;
    }
    push @stats, ($1, $2);
  }
  close $iptables;

  print $fh "<opcommand name='firewallrules'><format type='row'>\n";
  my $config = new Vyatta::Config;
  $config->setLevel("$root_hash{$tree} $tree $chain rule");
  my @rules = sort numerically $config->listOrigNodes();
  foreach (@rules) {
    my $rule = new Vyatta::IpTables::Rule;
    $rule->setupOrig("$root_hash{$tree} $tree $chain rule $_");
    $rule->set_ip_version($ip_version_hash{$tree});

    if (defined($rule_num) && $rule_num != $_) {
      next;
    }
    next if $rule->is_disabled();

    # just take the stats from the 1st iptables rule and remove unneeded stats
    # (if this rule corresponds to multiple iptables rules). note that
    # depending on how our rule is translated into multiple iptables rules,
    # this may actually need to be the sum of all corresponding iptables stats
    # instead of just taking the first pair. for eg: when protocol is tcp_udp
    # we aggregate the counters for both tcp and udp rules below
    my $pkts = shift @stats;
    my $bytes = shift @stats;
    if (defined $rule->{_protocol} && $rule->{_protocol} eq 'tcp_udp') {
      my @tmp_stats = @stats;
      if (defined $rule->{_log} && $rule->{_log} eq 'enable') {      
        # shift stats for 2 iptables rule
        shift @tmp_stats; shift @tmp_stats; shift @tmp_stats; shift @tmp_stats;
      } elsif (defined $rule->{_recent_time} || defined $rule->{_recent_cnt}) {
        # shift stats for 1 rule
        shift @tmp_stats; shift @tmp_stats;
      } 
      $pkts += shift @tmp_stats;
      $bytes += shift @tmp_stats;
    }
    my $ipt_rules = $rule->get_num_ipt_rules();
    splice(@stats, 0, (($ipt_rules - 1) * 2));
    $pkts = convert_to_easyunits($pkts);
    $bytes = convert_to_easyunits($bytes);
    print $fh "  <row>\n";
    print $fh "    <rule_number>$_</rule_number>\n";
    print $fh "    <pkts>$pkts</pkts>\n";
    print $fh "    <bytes>$bytes</bytes>\n";
    $rule->outputXml($fh);
    print $fh "  </row>\n";
  }

  if (!defined($rule_num) || ($rule_num == $max_rule)) {
    # dummy rule
    print $fh "  <row>\n";
    print $fh "    <rule_number>$max_rule</rule_number>\n";
    my $pkts = convert_to_easyunits(shift @stats);
    my $bytes = convert_to_easyunits(shift @stats);
    print $fh "    <pkts>$pkts</pkts>\n";
    print $fh "    <bytes>$bytes</bytes>\n";
    my $rule = new Vyatta::IpTables::Rule;
    $rule->setupDummy("$root_hash{$tree} $tree $chain");
    $rule->set_ip_version($ip_version_hash{$tree});
    $rule->outputXml($fh);
    print $fh "  </row>\n";
  }
  print $fh "</format></opcommand>\n";
}

sub show_chain_detail {

 my ($chain, $tree) = @_;
 my $table = $table_hash{$tree};
 my $iptables_cmd = $cmd_hash{$tree};

 my $config = new Vyatta::Config;
 $config->setLevel("$root_hash{$tree} $tree $chain rule");
 my @rules = sort numerically $config->listOrigNodes();
 print "\n";
 printf($format1, 'rule', 'action', 'proto', 'packets', 'bytes');
 print "\n";
 printf($format1, '----', '------', '-----', '-------', '-----');
 foreach (@rules) {
  my $rule = new Vyatta::IpTables::Rule;
  $rule->setupOrig("$root_hash{$tree} $tree $chain rule $_");
  if (defined($rule_num) && $rule_num != $_) {
      next;
  }
  next if $rule->is_disabled();
  print_detail_rule ($iptables_cmd, $table, $chain, $_, $tree);
 }
 if (!defined($rule_num) || ($rule_num == $max_rule)) {
  # dummy rule
  print_detail_rule ($iptables_cmd, $table, $chain, $max_rule, $tree);
 }
 print "\n";
}

sub print_detail_rule {
 my ($iptables_cmd, $table, $chain, $rule, $tree) = @_;
 my $string="";
 my $mul_lines="";
 my $udp_string = undef;
 
 # check from CLI if we have a condition set that creates more than 1 iptable rule
 # currenly LOG, RECENT, protocol tcp_udp in a CLI rule result in more than 1 iptable rule
 my $cli_rule = new Vyatta::IpTables::Rule;
 if ($rule eq $max_rule) {
   $cli_rule->setupDummy("$root_hash{$tree} $tree $chain");
   $cli_rule->set_ip_version($ip_version_hash{$tree});
 } else {
   $cli_rule->setupOrig("$root_hash{$tree} $tree $chain rule $rule");
 }
 if (defined $cli_rule->{_log} && "$cli_rule->{_log}" eq "enable") {
 
  # log enabled in rule so actual rule in iptables is second rule
  # now get line-num for 1st rule and use line-num+1 to list actual rule
   $mul_lines=`sudo /sbin/$iptables_cmd -t $table -L $chain -nxv --line-num |
              awk '/$chain-$rule / {print \$0}'`;
   my @lines = split(/\s+/, $mul_lines, 2);
   my $line_num = $lines[0] + 1;
   $string=`sudo /sbin/$iptables_cmd -t $table -L $chain $line_num -nxv |
              awk '/$chain-$rule / {print \$0}'`;

   if (defined $cli_rule->{_protocol} && $cli_rule->{_protocol} eq 'tcp_udp') {
     # we need the udp rule as well
     if (defined($cli_rule->{_recent_time}) || defined($cli_rule->{_recent_cnt})) { 
       $line_num = $line_num + 3;
     } else {
       $line_num = $line_num + 2;
     }
     $udp_string = `sudo /sbin/$iptables_cmd -t $table -L $chain $line_num -nxv |
                    awk '/$chain-$rule / {print \$0}'`;
   }
 } elsif ( (defined($cli_rule->{_recent_time}) || defined($cli_rule->{_recent_cnt})) ||
           (defined $cli_rule->{_protocol} && $cli_rule->{_protocol} eq 'tcp_udp') ) {
 
  # recent enabled but not log so actual rule in iptables is first rule
  # now get line-num for 1st rule and use that to list actual rule
   $mul_lines=`sudo /sbin/$iptables_cmd -t $table -L $chain -nxv --line-num |
              awk '/$chain-$rule / {print \$0}'`;
   my @lines = split(/\s+/, $mul_lines, 2);
   my $line_num = $lines[0];
   $string=`sudo /sbin/$iptables_cmd -t $table -L $chain $line_num -nxv |
              awk '/$chain-$rule / {print \$0}'`;
     
   # we need the udp rule as well         
   if (defined($cli_rule->{_recent_time}) || defined($cli_rule->{_recent_cnt})) {
     $line_num = $line_num + 2;
     $udp_string=`sudo /sbin/$iptables_cmd -t $table -L $chain $line_num -nxv |
              awk '/$chain-$rule / {print \$0}'`;
   } else {
     $line_num = $line_num + 1;
     $udp_string=`sudo /sbin/$iptables_cmd -t $table -L $chain $line_num -nxv |
              awk '/$chain-$rule / {print \$0}'`;
   }
 } else {
 
   # there's a one-to-one relation between our CLI rule and iptable rule
   $string=`sudo /sbin/$iptables_cmd -t $table -L $chain -nxv |
              awk '/$chain-$rule / {print \$0}'`;
 }
 
 my @string_words=();
 my @string_words_part1=();
 my @string_words_part2=();
 my @string_words_part3 = ();

 # trim leading and trailing whitespaces
 $string =~ s/^\s+|\s+$//g;
 @string_words = split (/\s+/, $string, 13);
 @string_words_part1=splice(@string_words, 0, 4); # packets, bytes, target, proto
 
 if (defined $cli_rule->{_protocol} && $cli_rule->{_protocol} eq 'tcp_udp') {
   $string_words_part1[3] = 'tcp_udp';
   
   # trim leading and trailing whitespaces
   $udp_string =~ s/^\s+|\s+$//g;
   # get udp rule packets, bytes
   my @udp_string_words=split(/\s+/, $udp_string, 13);
   @udp_string_words=splice(@udp_string_words, 0, 4); # packets, bytes, target, proto
   $string_words_part1[0] += $udp_string_words[0];
   $string_words_part1[1] += $udp_string_words[1];
 }

 if (defined $cli_rule->{_action}) {
  $string_words_part1[2]=$cli_rule->{_action};
 } else {
  $string_words_part1[2]='set';
 }
 
 if ($iptables_cmd =~ /6/) {
  @string_words_part2=splice(@string_words, 2, 2);# source, destination
 } else {
  @string_words_part2=splice(@string_words, 3, 2);# source, destination
 }
 if ($rule != $max_rule) {
  if ($iptables_cmd =~ /6/) {
   @string_words_part3=splice(@string_words, 5);# all other matches after comment
  } else {
   @string_words_part3=splice(@string_words, 6);# all other matches after comment
  }
 }
 my $condition='condition - ';
 my $string_for_part3 = join (" ", @string_words_part3);
 chomp $string_for_part3;
 $string_for_part3 = "daddr " . $string_words_part2[1] . " " .$string_for_part3;
 $string_for_part3 = "saddr " . $string_words_part2[0] . " " . $string_for_part3;

 # make output pretty, replace iptables specific information with CLI related text
 $string_for_part3 =~ s/ipp2p\s\S+\s/P2P /g;
 $string_for_part3 =~ s/multiport//g;
 $string_for_part3 =~ s/recent: UPDATE\s(.+)\sname: DEFAULT side: source /RECENT $1 /g;
 $string_for_part3 =~ s/limit: /LIMIT /g;
 while ($string_for_part3 =~ m/set\s(\S+)\ssrc\s/) {
  my $group_type=get_group_type("$1");
  $string_for_part3 =~ s/set\s(\S+)\ssrc\s/SRC-$group_type-GROUP $1 /;
 }
 while ($string_for_part3 =~ m/set\s(\S+)\sdst\s/) {
  my $group_type=get_group_type("$1");
  $string_for_part3 =~ s/set\s(\S+)\sdst\s/DST-$group_type-GROUP $1 /;
 }
 $string_for_part3 =~ s/policy match dir in pol\s(\S+)\s/IPSEC-MATCH $1 /g;
 if (defined $cli_rule->{_tcp_flags}) {
  $string_for_part3 =~ s/flags:(\S+)\s/tcp-flags $cli_rule->{_tcp_flags} /g;
 }
 
 # add information not displayed when listing the underlying iptable rule
 if (defined($cli_rule->{_frag})) {
   $string_for_part3 .= "FRAGMENT match-frag ";
 } elsif (defined($cli_rule->{_non_frag})) {
   $string_for_part3 .= "FRAGMENT match-non-frag ";
 }
 if (defined $cli_rule->{_log} && "$cli_rule->{_log}" eq "enable") {
  $string_for_part3 .= "LOG enabled";
 }

 print "\n";
 printf($format1, "$rule", "$string_words_part1[2]", "$string_words_part1[3]",
        "$string_words_part1[0]", "$string_words_part1[1]");
 
 print "\n";
 # print condition
 if ($string_for_part3 =~ /\w/) {
    while (length($string_for_part3) > 66) {
     my $condition_str = substr $string_for_part3, 0 , 66;
     $condition .= $condition_str;
     printf($format2, $condition);
     $condition = '            ';
     $string_for_part3 = substr $string_for_part3, 66;
     print "\n";
    }
    # print last line which has less than 66 chars
    $condition .= $string_for_part3;
    printf($format2, $condition);
 }
 print "\n";
}

sub get_group_type {
  my $group=shift;
  my $config = new Vyatta::Config;
  $config->setLevel("firewall group");
  my @addr_groups = $config->listOrigNodes("address-group");
  my @ntwrk_groups = $config->listOrigNodes("network-group");
  my @port_groups = $config->listOrigNodes("port-group");
  if (scalar(grep(/^$group$/, @addr_groups)) > 0) {
   return ("ADDR");
  } elsif (scalar(grep(/^$group$/, @ntwrk_groups)) > 0) {
    return ("NTWRK");
  } elsif (scalar(grep(/^$group$/, @port_groups)) > 0) {
    return ("PORT");
  }
}

sub show_tree {
  my ($tree, $config, ) = @_;

  my $description = $description_hash{$tree};
  $config->setLevel("$root_hash{$tree} $tree");
  my @chains = $config->listOrigNodes();
  my $chain_cnt=0;
  print "-" x 80 . "\n" if (scalar(@chains) > 0);
  foreach (sort @chains) {
    $chain_cnt++;
    print "$description \"$_\":";
    show_interfaces_zones($_, $tree);
    if (!($xsl_file =~ /detail/)) {
      open(RENDER, "| /usr/bin/xsltproc $xsl_file -") or exit 1;
      show_chain($_, *RENDER{IO}, $tree);
      close RENDER;
    } else {
      show_chain_detail($_, $tree);
    }
    print "-" x 80 . "\n" if ($chain_cnt < scalar(@chains));
  }
}

sub print_global_fw_header {
  print "\n" . "-" x 24 . "\n";
  print "Firewall Global Settings\n";
  print "-" x 24 . "\n";
}

sub print_fw_ruleset_header {
  print "\n" . "-" x 29 . "\n";
  print "Rulesets Information\n";
  print "-" x 29 . "\n";
}

sub show_state_policy {

  my $state_format = "%-15s %-8s %-8s";
  my @fw_states = ('invalid', 'established', 'related');
  my $fw_state_output = "";
  my $fw_state_set = "false";
  foreach my $state (@fw_states) {
    my $config = new Vyatta::Config;
    $config->setLevel("firewall state-policy $state");
    my ($action, $log_enabled) = (undef, undef);
    $log_enabled = $config->existsOrig("log enable");
    $action = $config->returnOrigValue("action");
    if (defined $action) {
      $fw_state_set = "true";
      last;
    }

  }

  if ($fw_state_set eq "true") {
    print_global_fw_header();
    print "\nFirewall state-policy for all IPv4 and Ipv6 traffic\n\n";
    printf($state_format, 'state', 'action', 'log');
    print "\n";
    printf($state_format, '-----', '------', '---');
    foreach my $state (@fw_states) {
      my $config = new Vyatta::Config;
      $config->setLevel("firewall state-policy $state");
      my ($action, $log_enabled) = (undef, undef);
      $log_enabled = $config->existsOrig("log enable");
      $action = $config->returnOrigValue("action");
      if (defined $action) {
        print "\n";
        printf($state_format, "$state", "$action", 'enabled') if defined $log_enabled;
        printf($state_format, "$state", "$action", 'disabled') if !defined $log_enabled;
      }
    }
    print "\n\n";
  }
  return;
}

#
# main
#

my $tree;
my $config = new Vyatta::Config;
my @chains;
my @tree_chain_name = split('_', $tree_chain, 2);
my $tree_name = $tree_chain_name[0];
my $chain_name = $tree_chain_name[1];

# check if tree name is either 'all' or one of four keys in %table_hash
if (!($tree_name eq "all" || (scalar(grep(/^$tree_name$/, (keys %table_hash))) > 0)
      || $tree_name eq "firewall" || $tree_name eq "policy")) {
 print "Invalid $root_hash{$tree} type name [$tree_name]\n";
 exit 1;
}

if ($tree_name eq "all") {
  show_state_policy();
  print_fw_ruleset_header();
  # Print all rule sets in all four trees
  foreach $tree (reverse(sort(keys %table_hash))) {
    show_tree($tree, $config);
  }
} elsif ($tree_name eq "firewall") {
  show_state_policy();
  print_fw_ruleset_header();
  show_tree('name', $config);
  show_tree('ipv6-name', $config);
} elsif ($tree_name eq "policy") {
  show_state_policy();
  print_fw_ruleset_header();
  show_tree('route', $config);
  show_tree('ipv6-route', $config);
} elsif ($chain_name eq "all") {
    show_state_policy();
    print_fw_ruleset_header();
    # Print all rule sets in specified tree
    $tree = $tree_name;
    show_tree($tree, $config);
} else {
  # Print given rule set in specified tree
    $tree = $tree_name;
    $config->setLevel("$root_hash{$tree} $tree");
    @chains = $config->listOrigNodes();
    # validate chain-name
    if (!(scalar(grep(/^$chain_name$/, @chains)) > 0)) {
     print "Invalid $root_hash{$tree} instance [$chain_name] \n";
     exit 1;
    }
    if (defined $rule_num) {
    #validate rule-num for given chain
     $config->setLevel("$root_hash{$tree} $tree $chain_name rule");
     my @rules = $config->listOrigNodes();
     if (!((scalar(grep(/^$rule_num$/, @rules)) > 0) || 
           ($rule_num == $max_rule))) {
      print "Invalid rule $rule_num under $root_hash{$tree} instance [$chain_name] \n";
      exit 1;
     }
    }
    show_state_policy();
    print_fw_ruleset_header();
    my $description = $description_hash{$tree};
    print "\n$description \"$chain_name\":";
    show_interfaces_zones($chain_name, $tree);
    if (!($xsl_file =~ /detail/)) {
     open(RENDER, "| /usr/bin/xsltproc $xsl_file -") or exit 1;
     show_chain($chain_name, *RENDER{IO}, $tree);
     close RENDER;
    } else {
      show_chain_detail($chain_name, $tree);
    }
}

exit 0;

# Local Variables:
# mode: perl
# indent-tabs-mode: nil
# perl-indent-level: 2
# End:
