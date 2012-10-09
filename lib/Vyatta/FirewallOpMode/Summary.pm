#!/usr/bin/perl
package Vyatta::FirewallOpMode::Summary;

use lib "/opt/vyatta/share/perl5/";
use Vyatta::Config;
use Vyatta::IpTables::Rule;
use Vyatta::IpTables::IpSet;
use Vyatta::IpTables::AddressFilter;
use Vyatta::Zone;
use Data::Dumper;

use warnings;
use strict;

sub show_interfaces_zones {
  my ($chain, $tree, $cfg, $cfg_ifs) = @_;
  $cfg->setLevel("");
  my $outhash = {};
  my @int_strs = ();
  my @zone_strs = ();
  my $content_str = "";
  for (@{$cfg_ifs}) {
    my ($iname, $ipath) = ($_->{name}, $_->{path});
    for my $dir ($cfg->listOrigNodes("$ipath firewall")) {
      my $ichain = $cfg->returnOrigValue("$ipath firewall $dir $tree");
      if (defined($ichain) and $ichain eq $chain) {
        $dir =~ y/a-z/A-Z/;
        push @int_strs, "($iname,$dir)";
      }
    }
  }
  $outhash->{'interfaces'} = \@int_strs;

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
       push @zone_strs, "zone [$zone] from $single_or_multiple_zone [$string_fromzones]";
     }
  }
  $outhash->{'zones'} = \@zone_strs;

  return $outhash; 
}

# mapping from config node to printable string describing it.
my %description_hash = ( 'name'        => 'IPv4',
                         'ipv6-name'   => 'IPv6',
                         'modify'      => 'IPv4 Modify',
                         'ipv6-modify' => 'IPv6 Modify');

sub show_tree {
  my ($tree, $config) = @_;
  my $tree_hash = {};
  my @cfg_ifs = Vyatta::Interface::get_effective_interfaces();
  my $description = $description_hash{$tree};
  $config->setLevel("firewall $tree");
  my @chains = $config->listOrigNodes();
  my $chain_cnt=0;
  foreach (sort @chains) {
    $chain_cnt++;
    $tree_hash->{$_}->{references} = show_interfaces_zones($_, $tree, $config, \@cfg_ifs);
    $config->setLevel("firewall $tree");
    $tree_hash->{$_}->{description} = $config->returnOrigValue("$_ description");
  }
  return $tree_hash;
}

sub show_state_policy {
  my ($config) = @_;
  my $outhash = {};
  my $state_format = "%-15s %-8s %-8s";
  my @fw_states = ('invalid', 'established', 'related');
  my $fw_state_output = "";
  my $fw_state_set = "false";
  foreach my $state (@fw_states) {
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
    foreach my $state (@fw_states) {
      $config->setLevel("firewall state-policy $state");
      my ($action, $log_enabled) = (undef, undef);
      $log_enabled = $config->existsOrig("log enable");
      $action = $config->returnOrigValue("action");
      if (defined $action) {
        $outhash->{$state}={ 'action' => $action, 'log' =>  defined($log_enabled) ? 'enabled' : 'disabled' };
      }
    }
  }
  return $outhash;
}

# Print all rule sets in all four trees
sub get_firewall_summary {
  my $config = new Vyatta::Config;
  my $hash = {};
  foreach my $tree (reverse(sort(keys %description_hash))) {
    $hash->{$tree} = show_tree($tree, $config);
    $hash->{global} = show_state_policy($config);
  }
  return $hash;
}

sub get_group_summary{
  my @lines = `ipset -L`;
  my $sets = {};
  foreach my $line (@lines) {
    if ($line =~ /^Name:\s+(\S+)$/ ) {
      my $set = $1;
      my $group = new Vyatta::IpTables::IpSet($set);
      next if ! $group->exists();
      my $desc    = $group->get_description();
      $desc = '' if ! defined($desc);
      my @fw_refs = $group->get_firewall_references();
      push @fw_refs, 'none' if scalar(@fw_refs) == 0;
      my $type    = $group->get_type();
      $sets->{$type}->{$set} = {
        'description' => $desc,
        'references' => \@fw_refs
      };
    }
  }
  return $sets; 
}

