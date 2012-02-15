#!/usr/bin/env perl
use lib '/opt/vyatta/share/perl5/';
use Vyatta::FirewallOpMode::Summary;

my %description_hash = ( 'name'        => 'IPv4',
                         'ipv6-name'   => 'IPv6',
                         'modify'      => 'IPv4 Modify',
                         'ipv6-modify' => 'IPv6 Modify');

my %gr_desc_hash = ( 'network' => 'Network',
                     'address' => 'Address',
                     'port' => 'Port');

sub print_global_fw_header {
  print "\n" . "-" x 24 . "\n";
  print "Firewall Global Settings\n";
  print "-" x 24 . "\n";
}

sub print_fw_ruleset_header {
  print "\n" . "-" x 24 . "\n";
  print "Firewall Rulesets\n";
  print "-" x 24 . "\n";
}

sub print_fw_group_header {
  print "\n" . "-" x 24 . "\n";
  print "Firewall Groups\n";
  print "-" x 24 . "\n";
}

my $hash = Vyatta::FirewallOpMode::Summary::get_firewall_summary();
print_global_fw_header;
if (scalar(keys(%{$hash->{'global'}})) > 0){
  my $state_format = "  %-15s %-8s %-8s\n";
  print "\nFirewall state-policy for all IPv4 and Ipv6 traffic\n\n";
  printf($state_format, 'state', 'action', 'log');
  printf($state_format, '-----', '------', '---');
  foreach my $state (keys(%{$hash->{'global'}})){
    printf $state_format, $state, 
           $hash->{'global'}->{$state}->{action}, 
           $hash->{'global'}->{$state}->{log};
  }
}
print_fw_ruleset_header;
my $format = "  %-26s%-15s%-s\n";
for my $tree (keys(%{$hash})){
  next if ($tree eq 'global');
  next if (scalar(keys(%{$hash->{$tree}})) == 0);
  print "\n$description_hash{$tree} name:\n\n";
  printf $format, 'Rule-set name', 'Description', 'References';
  printf $format, '-------------', '-----------', '----------';
  for my $chain (keys(%{$hash->{$tree}})){
    my $description = $hash->{$tree}->{$chain}->{description};
    my @intfs = @{$hash->{$tree}->{$chain}->{references}->{interfaces}};
    my @zones = @{$hash->{$tree}->{$chain}->{references}->{zones}};
    my $ci = $hash->{$tree}->{$chain}->{references}->{'content-inspection'};
    if (length($description) > 15){
       printf $format, $chain, $description, '';
       $description = '';
       $chain = ''; 
    }
    if (scalar(@intfs) > 0){
      my $intf_str = '';
      my $numintfs = 0;
      foreach my $intf (@intfs){
        $numintfs++;
        if ((length($intf_str) + length("$intf, ")) > 38) {
          printf $format, $chain, $description, $intf_str;
          ($chain, $description, $intf_str) = ('', '', '');
        }
        if ($numintfs < scalar(@intfs)){
          $intf_str .= "$intf, ";
        } else {
          if (scalar(@zones) > 0){
            $intf_str .= "$intf,";
          } else {
            $intf_str .= "$intf";
          } 
        }
      }
      printf $format, $chain, $description, $intf_str ;
      if (scalar(@zones) > 0){
        my $zone_str = '';
        my $numzones = 0;
        foreach my $zone (@zones){
          $numzones++;
          if ($numzones < scalar(@zones)){
            $zone_str .= "$zone, ";
          } else {
            $zone_str .= "$zone";
          }
        }
        if (length($zone_str) > 38){
          foreach my $zone (@zones){
            printf $format, '', '', $zone;
          }
        } else { 
          printf $format, '', '', $zone_str;
        }
      }
    } elsif (scalar(@zones) > 0){
      my $zone_str = '';
      my $numzones = 0;
      foreach my $zone (@zones){
        $numzones++;
        if ($numzones < scalar(@zones)){
          $zone_str .= "$zone, ";
        } else {
          $zone_str .= "$zone";
        }
      }
      if (length($zone_str) > 38){
        my $fzone = pop @zones;
        printf $format, $chain, $description, "$fzone,";
        my $numzones = 0;
        foreach my $zone (@zones){
          $numzones++;
          if ($numzones < scalar(@zones)){
            printf $format, '', '', "$zone,";
          } else { 
            printf $format, '', '', "$zone";
          }
        }
      } else {
        printf $format, $chain, $description, "$zone_str";
      } 
    }
  }
  print "\n";
}
my $gr_hash = Vyatta::FirewallOpMode::Summary::get_group_summary();
print_fw_group_header;
foreach my $type (keys(%{$gr_hash})){
  print "\n$gr_desc_hash{$type} Groups:\n\n";
  printf $format, 'Group name', 'Description', 'References';
  printf $format, '----------', '-----------', '----------';
  foreach my $group (keys(%{$gr_hash->{$type}})){
    my $description = $gr_hash->{$type}->{$group}->{'description'};
    my @refs = @{$gr_hash->{$type}->{$group}->{'references'}};
    my $numrefs = 0;
    if (scalar(@refs) > 0) {
      my $fref = pop @refs;
      $fref = "$fref," if (scalar(@refs) > 0);
      if (length($description) > 15) {
        printf $format, $group, $description, '';
        printf $format, '', '', $fref;
      } else {
        printf $format, $group, $description, $fref;
      }
      foreach my $ref (@refs){
        $numrefs++;
        if ($numrefs < scalar(@refs)) {
          printf $format, '', '', "$ref, ";
        } else {
          printf $format, '', '', $ref;
        } 
      }
    }
  }
  print "\n";
}
